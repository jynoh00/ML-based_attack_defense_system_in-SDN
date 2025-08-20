const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    console.log('more.js Router running : index.ejs render');
    res.render('index');
});

router.get('/background', (req, res) => {
    console.log('more.js Router running : bg.ejs render');
    res.render('bg');
});

router.get('/flowchart', (req, res) => {
    console.log('more.js Router running : flowchart.ejs render');
    res.render('flowchart');
});

router.get('/webUI', (req, res) => {
    console.log('more.js Router running : webUI.ejs render');
    res.render('webUI');
});

module.exports = router;