use core::{arch::asm, cell::{RefCell, UnsafeCell}, fmt::Error, sync::atomic::{AtomicBool, Ordering}};

use alloc::{boxed::Box, string::{String, ToString}, sync::Arc, vec::Vec};

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

pub struct Mutex<T> {
    lock: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Mutex {
            lock: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock<'a>(&'a self) -> MutexGuard<'a, T> {
        while self.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            // Busy-wait until the lock is acquired
            core::hint::spin_loop();
        }
        MutexGuard { mutex: self }
    }

    pub fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }
}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<'a, T> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

impl<'a, T> core::ops::Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.data.get() }
    }
}

#[derive(Debug)]
pub struct RingBuffer<T> {
    buffer: Vec<Option<T>>,
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
            self.buffer.push(Some(item));
        } else {
            self.buffer[self.tail] = Some(item);
        }

        self.tail = (self.tail + 1) % self.capacity;
        self.size += 1;

        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        let item = core::mem::replace(&mut self.buffer[self.head], None);
        self.head = (self.head + 1) % self.capacity;
        self.size -= 1;

        Some(item.unwrap())
    }

    pub fn len(&self) -> usize {
        self.size
    }
}


pub struct Deque<T> {
    data: Vec<T>,
}

impl<T> Deque<T> {
    pub fn new() -> Self {
        Deque {
            data: Vec::new(),
        }
    }

    pub fn push_front(&mut self, value: T) {
        self.data.insert(0, value);
    }

    pub fn push_back(&mut self, value: T) {
        self.data.push(value);
    }

    pub fn pop_front(&mut self) -> Option<T> {
        if self.data.is_empty() {
            None
        } else {
            Some(self.data.remove(0))
        }
    }

    pub fn pop_back(&mut self) -> Option<T> {
        self.data.pop()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn front(&self) -> Option<&T> {
        self.data.first()
    }

    pub fn back(&self) -> Option<&T> {
        self.data.last()
    }
}

pub struct Channel<T> {
    buffer: Arc<Mutex<Deque<T>>>,
    capacity: usize,
}

// implement clone for Channel
impl<T> Clone for Channel<T> {
    fn clone(&self) -> Self {
        Channel { buffer: self.buffer.clone(), capacity: self.capacity }
    }
}


//  a Sender and Receiver pair
pub struct Sender<T> {
    channel: Channel<T>,
}

pub struct Receiver<T> {
    channel: Channel<T>,
}


impl< T> Sender<T> {
    pub fn new(channel: Channel<T>) -> Self {
        Sender { channel }
    }

    pub fn send(&mut self, item: T) -> Result<(), String> {
        self.channel.send(item)
    }

    pub fn send_priority(&mut self, item: T) -> Result<(), String> {
        self.channel.send_priority(item)
    }
}

impl< T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Sender { channel: self.channel.clone() }
    }
}

impl< T> Receiver< T> {
    pub fn new(channel: Channel<T>) -> Self {
        Receiver { channel }
    }

    pub fn recv(&mut self) -> T {
        self.channel.recv()
    }
}

impl <T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        Receiver { channel: self.channel.clone() }
    }
}


impl<T> Channel<T> {
    pub fn new<'a>(capacity: usize) -> (Sender<T>, Receiver<T>) {
        let mut ch: Channel<T> = Channel {
            buffer: Arc::new(Mutex::new(Deque::new())),
            capacity,
        };
        let sender = Sender::new(ch.clone());
        let receiver = Receiver::new(ch.clone());
        (sender, receiver)
    }

    fn send(&mut self, item: T) -> Result<(), String> {
        let mut buffer = self.buffer.lock();
        if buffer.len() >= self.capacity {
            return Err("Buffer is full".to_string());
        }
        buffer.push_back(item);
        Ok(())
    }
    
    fn send_priority(&mut self, item: T) -> Result<(), String> {
        let mut buffer = self.buffer.lock();
        buffer.push_front(item);
        Ok(())
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
            if let Some(item) = buffer.pop_front() {
                return item;
            }
            core::hint::spin_loop();
        }
    }
}
