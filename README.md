# Rust Landlock library

Landlock is a security feature available since Linux 5.13.
The goal is to enable to restrict ambient rights (e.g., global filesystem access) for a set of processes by creating safe security sandboxes as new security layers in addition to the existing system-wide access-controls.
This kind of sandbox is expected to help mitigate the security impact of bugs, unexpected or malicious behaviors in applications.
Landlock empowers any process, including unprivileged ones, to securely restrict themselves.
More information about Landlock can be found in the [official website](https://landlock.io).

This Rust crate provides a safe abstraction for the Landlock system calls along with some helpers.
See the [Rust Landlock API documentation](https://landlock.io/rust-landlock/landlock/).
