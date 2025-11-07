# CW2_CST1500

A Multi-Domain Intelligence Platform for CST1510, built with Python and Streamlit to analyse data for Cybersecurity, Data Science, and IT Operations.

Week 7: Secure Authentication System

Student Name: Kavirajduthsingh Ramdawor
Student ID: M01068425
Course: CST1510-CW2 - Multi-Domain Intelligence Platform

Project Description:
A command-line authentication system implementing secure password hashing.
This system allows users to register accounts and log in with proper password verification, ensuring that no plaintext passwords are ever stored.

Features:
Secure password hashing using bcrypt with automatic salt generation.
User registration with duplicate username prevention.
User login with secure password verification.
Input validation for usernames and passwords.
File-based user data persistence (users.txt).

Optional Challenge Features Implemented:
Password Strength Indicator: Rates password strength as "Weak", "Medium", or "Strong" during registration.
User Role System: Allows registration of users with different roles (e.g., user, admin, analyst).
Account Lockout: Locks an account for 5 minutes after 3 consecutive failed login attempts to prevent brute-force attacks.
Session Management: Generates a secure session token (using secrets) upon successful login.

Technical Implementation:
Hashing Algorithm: bcrypt with automatic salting.
Data Storage: Plain text file (users.txt) with comma-separated values (CSV) in the format: username,hashed_password,role.
Password Security: One-way hashing ensures no plaintext passwords are stored.
Validation -
Username: 3-20 alphanumeric characters.
Password: 6-50 characters, requiring at least one uppercase letter, one lowercase letter, and one digit.
