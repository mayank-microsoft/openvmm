use core::{arch::asm, cell::RefCell, fmt::Error, sync::atomic::AtomicBool};

use alloc::{string::{String, ToString}, sync::Arc, vec::Vec};

use crate::logt;

// pub struct LazyLock<T> {
//     lock: AtomicBool,
//     init: fn() -> T,
//     val: Option<RefCell<T>>,
// }

// impl<T> LazyLock<T> {
//     pub fn new(init: fn() -> T) -> Self {
//         LazyLock {
//             lock: AtomicBool::new(false),
//             init,
//             val: None,
//         }
//     }

//     pub fn get(&mut self) -> &T {
//         if let ok = self.lock.get_mut() {
//             if *ok {
//                 self.val = Some(RefCell::new((self.init)()));

//             }
//         }
//         if let Some(ref val) = self.val {
//             return &val.borrow();
//         }
//         panic!("LazyLock not initialized");
//     }

//     pub fn get_mut(&mut self) -> &mut T {
//         if let ok = self.lock.get_mut() {
//             if ok {
//                 self.val = Some((self.init)());
//             }
//         }
//         &mut self.val.unwrap()
//     }
// }

#[derive(Debug)]
pub struct Mutex<T> {
    pub lock: AtomicBool,
    pub val: T,
}

pub struct Guard<'a, T> {
    mutex: &'a mut Mutex<T>,
}

impl<'a, T> Guard<'a, T> {
    pub fn get(&self) -> &T {
        &self.mutex.val
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.mutex.val
    }
}

impl<'a, T> Drop for Guard<'a, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

unsafe impl<T> Send for Mutex<T> {}
unsafe impl<T> Sync for Mutex<T> {}
impl<'a, T> Mutex<T> {
    pub const fn new(val: T) -> Self {
        Mutex {
            lock: AtomicBool::new(false),
            val,
        }
    }

    pub fn lock(&'a mut self) -> Guard<'a, T> {
        loop {
            let mut lk = self.lock.get_mut();
            if !*lk {
                *lk = true;
                break;
            }
            core::hint::spin_loop();
        }
        Guard { mutex: self }
    }

    fn unlock(&mut self) {
        let mut lk = self.lock.get_mut();
        *lk = false;
    }
}

impl<T> Drop for Mutex<T> {
    fn drop(&mut self) {
        self.unlock();
    }
}


#[derive(Debug)]
pub struct RingBuffer<T> {
    buffer: Vec<T>,
    capacity: usize,
    head: usize,
    tail: usize,
    size: usize,
}

impl<T> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        RingBuffer {
            buffer: Vec::with_capacity(capacity),
            capacity,
            head: 0,
            tail: 0,
            size: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.size == 0
    }

    fn is_full(&self) -> bool {
        self.size == self.capacity
    }

    pub fn push(&mut self, item: T) -> Result<(), String> {
        if self.is_full() {
            return Err("Buffer is full".to_string());
        }

        if self.tail == self.buffer.len() {
            self.buffer.push(item);
        } else {
            self.buffer[self.tail] = item;
        }

        self.tail = (self.tail + 1) % self.capacity;
        self.size += 1;

        logt!("Ok size: {}", self.size);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        logt!("state[head]: {:?}", self.head);
        logt!("state[cap]: {:?}", self.capacity);
        logt!("state[sz]: {:?}", self.size);
        logt!("state[len]: {:?}", self.buffer.len());
        
        let item = core::mem::replace(&mut self.buffer[self.head], unsafe {
            core::mem::zeroed()
        });

        self.head = (self.head + 1) % self.capacity;
        self.size -= 1;

        Some(item)
    }

    pub fn len(&self) -> usize {
        self.size
    }
}


pub struct Channel<T> {
    buffer: Arc<Mutex<RingBuffer<T>>>,
}

// implement clone for Channel
impl<T> Clone for Channel<T> {
    fn clone(&self) -> Self {
        Channel { buffer: self.buffer.clone() }
    }
}


//  a Sender and Receiver pair
pub struct Sender<'a,T> {
    channel: &'a mut Channel<T>,
}

pub struct Receiver<'a, T> {
    channel: &'a mut Channel<T>,
}
impl<'a, T> Sender<'a, T> {
    pub fn new(channel: &'a mut Channel<T>) -> Self {
        Sender { channel }
    }

    pub fn send(&mut self, item: T) -> Result<(), String> {
        self.channel.send(item)
    }
}
impl<'a, T> Receiver<'a, T> {
    pub fn new(channel:&'a mut Channel<T>) -> Self {
        Receiver { channel }
    }

    pub fn recv(&mut self) -> T {
        self.channel.recv()
    }
}

impl<T> Channel<T> {
    pub fn new<'a>(capacity: usize) -> Self {
        let mut ch: Channel<T> = Channel {
            buffer: Arc::new(Mutex::new(RingBuffer::new(capacity))),
        };
        ch
    }

    fn send(&mut self, item: T) -> Result<(), String> {
        let mut buffer = &mut *self.buffer  ;

        let mut buffer = self.buffer.lock();
        buffer.get_mut().push(item)
    }

    fn recv(&mut self) -> T {
        loop {
            unsafe {
                asm!("nop");
                asm!("nop");
                asm!("nop");
                asm!("nop");
                asm!("nop");
                asm!("nop");
                asm!("nop");
                asm!("nop");
            }
            let mut buffer = self.buffer.lock();
            logt!("recv1");
            if !buffer.get_mut().pop().is_none() {
                return buffer.get_mut().pop().unwrap();
            }
            core::hint::spin_loop();
        }
    }
}
