# 🔐 Secure Login System (Flask)

A secure authentication system built using Flask that allows users to register, log in, and access protected pages with session-based authentication.

## 🚀 Features

- User registration with validation
- Secure password hashing (PBKDF2)
- Login authentication with session management
- Account lockout after multiple failed attempts
- Protected routes (Dashboard & Profile)
- Flash messaging for user feedback
- Clean UI with reusable templates

## 🛠️ Tech Stack

- Python
- Flask
- SQLite
- HTML / Jinja Templates
- CSS

## 🔒 Security Features

- Password hashing using PBKDF2 (200,000 iterations)
- Unique salt per user
- Protection against brute-force attacks (account lockout)
- Secure session handling
- Input validation for usernames and passwords

## 📂 Project Structure
