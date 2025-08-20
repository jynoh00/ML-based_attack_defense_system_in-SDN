const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    console.log('index.js Router running : index.ejs render');
    res.render('index');
});

module.exports = router;