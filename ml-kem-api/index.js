const express = require("express");
const cors = require("cors");
const { execFile } = require("child_process");
const path = require("path");
const app = express();
const port = 3050;

app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.static(path.join(__dirname, 'public')));

const BIN_DIR = path.resolve(__dirname, "../build");

// Endpoint: Key Generation
app.get("/keygen", (req, res) => {
    execFile(`${BIN_DIR}/mlkem_keygen`, (err, stdout, stderr) => {
        if (err) return res.status(500).send(stderr);
        const [pubkey, secretkey] = stdout.trim().split('\n');
        res.json({ pubkey, secretkey });
    });
});

const isHex = (s) => /^[0-9a-fA-F]+$/.test(s);

app.post("/encaps", (req, res) => {
    const pubkey = req.body.pubkey;
    if (!pubkey || !isHex(pubkey)) return res.status(400).send("Invalid pubkey");

    execFile(`${BIN_DIR}/mlkem_encaps`, [pubkey], (err, stdout, stderr) => {
        if (err) return res.status(500).send(stderr);
        const [shared, ciphertext] = stdout.trim().split('\n');
        res.json({ shared, ciphertext });
    });
});

app.post("/decaps", (req, res) => {
    const { secretkey, ciphertext } = req.body;
    if (!secretkey || !ciphertext || !isHex(secretkey) || !isHex(ciphertext))
        return res.status(400).send("Invalid secretkey or ciphertext");

    execFile(`${BIN_DIR}/mlkem_decaps`, [secretkey, ciphertext], (err, stdout, stderr) => {
        if (err) return res.status(500).send(stderr);
        const shared = stdout.trim();
        res.json({ shared });
    });
});

app.listen(port, () => {
    console.log(`✅ ML-KEM API running at http://localhost:${port}`);
});
