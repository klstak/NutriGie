const dotenv = require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// Konfigurasi koneksi ke database MySQL
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
});

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
    } else {
        console.log('Connected to database');
    }
});

module.exports = connection;




// Route untuk registrasi
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Enkripsi password menggunakan bcrypt
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: 'Terjadi kesalahan saat mengenkripsi password'
            });
        }

        // Simpan data pengguna baru ke database
        const user = {
            username,
            password: hash
        };
        connection.query('INSERT INTO users SET ?', user, (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: 'Terjadi kesalahan saat mendaftarkan pengguna baru'
                });
            }

            return res.status(201).json({
                message: 'Registrasi berhasil'
            });
        });
    });
});

// Route untuk login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Cari pengguna dengan username yang diberikan
    connection.query('SELECT * FROM users WHERE username = ?', username, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: 'Terjadi kesalahan saat mencari pengguna'
            });
        }

        // Periksa apakah pengguna ditemukan
        if (results.length === 0) {
            return res.status(401).json({
                error: 'Username atau password salah'
            });
        }

        const user = results[0];

        // Periksa kecocokan password menggunakan bcrypt
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: 'Terjadi kesalahan saat memeriksa password'
                });
            }

            if (!isMatch) {
                return res.status(401).json({
                    error: 'Username atau password salah'
                });
            }

            // Buat token JWT untuk autentikasi
            const token = jwt.sign(
                { userId: user.id, username: user.username },
                process.env.SECRET_KEY,
                { expiresIn: '1h' } // Ubah sesuai kebutuhan
            );

            return res.status(200).json({
                message: 'Login berhasil',
                token
            });
        });
    });
});

// Middleware untuk memeriksa token JWT pada setiap permintaan
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.status(401).json({
            error: 'Token autentikasi tidak ditemukan'
        });
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            console.error(err);
            return res.status(403).json({
                error: 'Token autentikasi tidak valid'
            });
        }
        req.user = user;
        next();
    });
}

// Contoh route yang memerlukan autentikasi
app.get('/protected', authenticateToken, (req, res) => {
    // Lakukan aksi yang diinginkan setelah autentikasi sukses
    return res.json({
        message: 'Akses berhasil ke rute yang dilindungi'
    });
});

// Route untuk input data diri pengguna
app.post('/profile', authenticateToken, (req, res) => {
    const { height, weight, age } = req.body;
    const userId = req.user.userId;

    const profile = {
        user_id: userId,
        height,
        weight,
        age
    };

    connection.query('INSERT INTO profiles SET ?', profile, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: 'Terjadi kesalahan saat menyimpan data diri'
            });
        }

        return res.status(201).json({
            message: 'Data diri tersimpan'
        });
    });
});


// Menjalankan server pada port tertentu
app.listen(3000, () => {
    console.log('Server berjalan pada port 3000');
});
