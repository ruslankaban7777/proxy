const express = require('express');
const fetch = require('node-fetch');
const app = express();
const port = 3000;

app.use(express.json());

app.post('/check-file', async (req, res) => {
    const file = req.body.file; // Файл в base64
    const apiKey = "ВАШ_API_КЛЮЧ";

    const response = await fetch('https://www.virustotal.com/api/v3/files', {
        method: 'POST',
        headers: {
            'x-apikey': apiKey,
        },
        body: file,
    });

    const data = await response.json();
    res.json(data);
});

app.listen(port, () => {
    console.log(`Прокси-сервер запущен на http://localhost:${port}`);
});