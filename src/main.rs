#![no_std]
#![no_main]

use core::{cell::RefCell, convert::TryInto, sync::atomic};

use adafruit_mp3_sys::ffi::*;
use cortex_m_rt::entry;
use critical_section::Mutex;
use defmt::*;
use defmt_rtt as _;
use embedded_hal::digital::v2::OutputPin;
use panic_probe as _;

use rp_pico as bsp;

use bsp::hal::{
    self,
    clocks::{ClocksManager, InitError},
    pac,
    pac::interrupt,
    pll::{common_configs::PLL_USB_48MHZ, PLLConfig},
    pwm::{FreeRunning, Pwm3},
    sio::Sio,
    watchdog::Watchdog,
};

static MP3: &[u8] = include_bytes!("../vampire_killer_44khz_loop.mp3");

// GPIO traits
use embedded_hal::PwmPin;

use fugit::RateExtU32;

struct SampleBuffer {
    size: u16,
    idx: u16,
    buf: [u16; 4608 / 2],
}
impl SampleBuffer {
    pub const fn new() -> Self {
        SampleBuffer {
            size: 0,
            idx: 0,
            buf: [0u16; 4608 / 2],
        }
    }
}
static READY_FOR_MORE: atomic::AtomicBool = atomic::AtomicBool::new(true);
static SAMPLES: Mutex<RefCell<Option<SampleBuffer>>> = Mutex::new(RefCell::new(None));

/// The hardware PWM driver that is shared with the interrupt routine.
static mut PWM: Option<hal::pwm::Slice<Pwm3, FreeRunning>> = None;

/// Initialize system clocks and PLLs according to specified configs
#[allow(clippy::too_many_arguments)]
fn init_clocks_and_plls_cfg(
    xosc_crystal_freq: u32,
    xosc_dev: pac::XOSC,
    clocks_dev: pac::CLOCKS,
    pll_sys_dev: pac::PLL_SYS,
    pll_usb_dev: pac::PLL_USB,
    pll_sys_cfg: PLLConfig,
    pll_usb_cfg: PLLConfig,
    resets: &mut pac::RESETS,
    watchdog: &mut Watchdog,
) -> Result<ClocksManager, InitError> {
    let xosc = hal::xosc::setup_xosc_blocking(xosc_dev, xosc_crystal_freq.Hz())
        .map_err(InitError::XoscErr)?;

    // Configure watchdog tick generation to tick over every microsecond
    watchdog.enable_tick_generation((xosc_crystal_freq / 1_000_000) as u8);

    let mut clocks = ClocksManager::new(clocks_dev);

    let pll_sys = hal::pll::setup_pll_blocking(
        pll_sys_dev,
        xosc.operating_frequency().into(),
        pll_sys_cfg,
        &mut clocks,
        resets,
    )
    .map_err(InitError::PllError)?;
    let pll_usb = hal::pll::setup_pll_blocking(
        pll_usb_dev,
        xosc.operating_frequency().into(),
        pll_usb_cfg,
        &mut clocks,
        resets,
    )
    .map_err(InitError::PllError)?;

    clocks
        .init_default(&xosc, &pll_sys, &pll_usb)
        .map_err(InitError::ClockError)?;
    Ok(clocks)
}

#[entry]
fn main() -> ! {
    info!("Program start");
    let mut pac = pac::Peripherals::take().unwrap();
    let _core = pac::CorePeripherals::take().unwrap();
    let mut watchdog = Watchdog::new(pac.WATCHDOG);
    let sio = Sio::new(pac.SIO);

    // Output from vocalc.py
    // This clock rate is closest to 176,400,000 Hz, which is a multiple of 44,100 Hz.
    let pll_sys_176mhz: PLLConfig = PLLConfig {
        vco_freq: 528u32.MHz(),
        refdiv: 1,
        post_div1: 3,
        post_div2: 1,
    };

    // Configure the clocks
    // Note that we choose a nonstandard system clock rate, so that we can closely
    // control the PWM cycles so that they're (close to) a multiple of the audio sample rate.
    let _clocks = init_clocks_and_plls_cfg(
        bsp::XOSC_CRYSTAL_FREQ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        pll_sys_176mhz,
        PLL_USB_48MHZ,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .ok()
    .unwrap();
    // The single-cycle I/O block controls our GPIO pins
    // Set the pins up according to their function on this particular board
    let pins = bsp::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    // Init PWMs
    let pwm_slices = hal::pwm::Slices::new(pac.PWM, &mut pac.RESETS);

    // Setup the LED pin
    let mut led_pin = pins.led.into_push_pull_output();
    // Set the VREG to PWM mode to reduce noise
    let mut psu_pin = pins.b_power_save.into_push_pull_output();
    psu_pin.set_high().unwrap();
    // Configure PWM3
    let mut pwm = pwm_slices.pwm3;
    pwm.default_config();

    pwm.set_top(4096);
    pwm.set_div_int(1);
    pwm.channel_a.set_duty(0);

    pwm.enable_interrupt();
    pwm.enable();
    // Output channel A on PWM3 to GPIO22
    pwm.channel_a.output_to(pins.gpio22);

    unsafe {
        // Share the PWM with our interrupt routine.
        PWM = Some(pwm);

        // Unmask the PWM_IRQ_WRAP interrupt so we start receiving events.
        pac::NVIC::unmask(pac::interrupt::PWM_IRQ_WRAP);
    }

    type Mp3ptrT = *const u8;
    let mp3baseptr: Mp3ptrT = MP3.as_ptr();
    info!("address of the start of MP3: {:?}", mp3baseptr);
    let mut bytes_left = MP3.len() as i32;
    // this sets up the buffers that the mp3 decode uses
    let mp3dec = unsafe { adafruit_mp3_sys::ffi::MP3InitDecoder() };
    // gotta look for the first audio frame
    let start = unsafe { adafruit_mp3_sys::ffi::MP3FindSyncWord(mp3baseptr, bytes_left) };
    bytes_left -= start;
    let mut frame: _MP3FrameInfo = _MP3FrameInfo {
        bitrate: 0,
        nChans: 0,
        samprate: 0,
        bitsPerSample: 0,
        outputSamps: 0,
        layer: 0,
        version: 0,
    };

    info!("start: {}", start);
    'mainloop: loop {
        // Update our MP3 pointer to skip past the id3 tags (hopefully)
        let mut mp3ptr: Mp3ptrT = mp3baseptr.wrapping_add(start.try_into().unwrap());

        // if we have the first frame we should be able to determine what sort of mp3 this is
        info!("Address of the first valid frame of mp3 {:?}", mp3ptr);
        let f = unsafe { MP3GetNextFrameInfo(mp3dec, &mut frame, mp3ptr) };
        info!("MP3GetNextFrameInfo response: {:?}", f);
        info!(
            "info: bitrate {}, channels {}, samplerate {}, bits/sample {}, output samples {}, layer {}, version {}",
            frame.bitrate,
            frame.nChans,
            frame.samprate,
            frame.bitsPerSample,
            frame.outputSamps,
            frame.layer,
            frame.version,
        );

        let decode_len = (frame.bitsPerSample >> 3) * frame.outputSamps;
        info!("decoded_len = {}", decode_len);
        let mut newlen = bytes_left as i32;
        // This buffer length is what I got for a 44Khz mono MP3
        // it is effectively decode_len from above (bytes/2 because buf is u16)
        let mut buf = [0i16; 4608 / 2];

        'decodeloop: while newlen > 0 {
            // info!("remaining bytes: {}", newlen);
            let old_newlen = newlen;
            // Decode some MP3 into our sample buffer
            let decoded =
                unsafe { MP3Decode(mp3dec, &mut mp3ptr, &mut newlen, buf.as_mut_ptr(), 0) };
            if decoded != 0 {
                let decodedstr = match decoded {
                    0 => "Okay",
                    -1 => "ERR_MP3_INDATA_UNDERFLOW",
                    -2 => "ERR_MP3_MAINDATA_UNDERFLOW",
                    -3 => "ERR_MP3_FREE_BITRATE_SYNC",
                    -4 => "ERR_MP3_OUT_OF_MEMORY",
                    -5 => "ERR_MP3_NULL_POINTER",
                    -6 => "ERR_MP3_INVALID_FRAMEHEADER",
                    -7 => "ERR_MP3_INVALID_SIDEINFO",
                    -8 => "ERR_MP3_INVALID_SCALEFACT",
                    -9 => "ERR_MP3_INVALID_HUFFCODES",
                    -10 => "ERR_MP3_INVALID_DEQUANTIZE",
                    -11 => "ERR_MP3_INVALID_IMDCT",
                    -12 => "ERR_MP3_INVALID_SUBBAND",
                    -9999 => "ERR_UNKNOWN",
                    _ => "ERR_INVALID_ERROR",
                };
                info!("Decoded {}", decodedstr);

                if old_newlen == newlen {
                    // no point in continuing to process the same data
                    continue 'mainloop;
                }
                if decoded == -1 {
                    // no point in continuing to decode if we run out of data
                    continue 'mainloop;
                }
                // we had an error with this frame, maybe the next one will be better...
                continue 'decodeloop;
            }
            unsafe { MP3GetLastFrameInfo(mp3dec, &mut frame) };

            // Okay, we've decoded a frame, but now we need to send it somewhere
            let mut newbuf = SampleBuffer::new();
            // Convert from 16bit signed to some number of PWM bits, unsigned
            for (s, t) in core::iter::zip(buf.iter(), newbuf.buf.iter_mut()) {
                let unsigned_sample = (*s as i32 + 32768) as u16;
                // 12 bits
                let i = (unsigned_sample >> 4) & 0xFFF;
                *t = i;
            }
            newbuf.size = frame.outputSamps as u16;
            'wait_for_buf: loop {
                // wait until the buffer is free for us to send some data
                let is_none = READY_FOR_MORE.load(atomic::Ordering::Acquire);
                if is_none {
                    break 'wait_for_buf;
                }
                // If we're here, the buffer is in use.
                // it won't be free until the IRQ handler frees it
                // so sleep until then
                let _ = led_pin.set_high();
                cortex_m::asm::wfi();
                let _ = led_pin.set_low();
            }
            // we broke out of 'wait_for_buf, so the buffer must be free. replace it with our decoded data.
            critical_section::with(|cs| {
                SAMPLES.replace(cs, Some(newbuf));
                READY_FOR_MORE.store(false, atomic::Ordering::Release);
            });
        }
    }
}

#[interrupt]
fn PWM_IRQ_WRAP() {
    // we keep a local sample buffer so that the CPU can fill one while waiting
    static mut IRQ_SAMPLES: SampleBuffer = SampleBuffer::new();

    // if we've run out of samples in our local buffer, take the global one
    if IRQ_SAMPLES.size == 0 {
        critical_section::with(|cs| {
            if let Some(glob_samples) = SAMPLES.borrow(cs).take() {
                *IRQ_SAMPLES = glob_samples
            }
        });
    }
    let pwm = unsafe { &mut PWM }.as_mut().unwrap();
    // Don't process an empty buffer - CPU must not have filled it fast enough
    if IRQ_SAMPLES.size != 0 {
        let sample_idx = IRQ_SAMPLES.idx;
        let size = IRQ_SAMPLES.size;
        // if our buffer has data it in, process the next sample
        if sample_idx < size {
            let sample = IRQ_SAMPLES.buf.get(sample_idx as usize).unwrap();
            let channel = &mut pwm.channel_a;
            channel.set_duty(*sample);
            IRQ_SAMPLES.idx = sample_idx + 1;
        } else {
            info!("out of data?");
        }
        // if that was the last sample, let the main thread know right now!
        if IRQ_SAMPLES.idx >= size {
            // flag that our buffer is empty
            IRQ_SAMPLES.size = 0;
            READY_FOR_MORE.store(true, atomic::Ordering::Release);
        }
    } else {
        // info!("out of data? (we'll hit this until we fill the buffer the first time)");
        // could wait until the buffer is filled to enable PWM. probably not worth it.
    }
    // Clear the interrupt (so we don't immediately re-enter this routine)
    pwm.clear_interrupt();
}

// End of file
