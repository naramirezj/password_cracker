# password_cracker
Recover a list of user’s passwords from a database of MD5-hashed passwords implementing POSIX multithreading. The program will use four threads to concurrently check candidate passwords within the database in parallel. The threads will equally divide the searching with appropriate synchronization to prevent race conditions
