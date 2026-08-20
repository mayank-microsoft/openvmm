// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_arch = "x86_64")]

// Entry point.
#[cfg(minimal_rt)]
core::arch::global_asm! {
    include_str!("entry.S"),
    start = sym crate::rt::start,
    stack = sym crate::rt::STACK,
    STACK_COOKIE = const crate::rt::STACK_COOKIE,
    STACK_SIZE = const crate::rt::STACK_SIZE,
}
