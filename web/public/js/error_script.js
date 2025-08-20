document.querySelectorAll('.btn').forEach(btn => {
    btn.addEventListener('click', function(e) {
        const ripple = document.createElement('span');
        const rect = this.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        ripple.style.width = ripple.style.height = size + 'px';
        ripple.style.left = x + 'px';
        ripple.style.top = y + 'px';
        ripple.style.position = 'absolute';
        ripple.style.borderRadius = '50%';
        ripple.style.background = 'rgba(255, 255, 255, 0.6)';
        ripple.style.transform = 'scale(0)';
        ripple.style.animation = 'ripple 0.6s linear';
        ripple.style.pointerEvents = 'none';
        
        this.appendChild(ripple);
        
        setTimeout(() => {
            ripple.remove();
        }, 600);
    });
});

const style = document.createElement('style');
style.textContent = `
    @keyframes ripple {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

document.addEventListener('keydown', function(e) {
    if (e.code === 'Space') {
        e.preventDefault();
        goHome();
    } else if (e.key === 'Escape') {
        goBack();
    }
});

window.addEventListener('load', function() {
    const errorCode = document.querySelector('.error-code');
    let count = 0;
    const target = 404;
    const increment = target / 30;
    
    const counter = setInterval(() => {
        count += increment;
        if (count >= target) {
            count = target;
            clearInterval(counter);
        }
        errorCode.textContent = Math.floor(count);
    }, 30);
});

function goHome() {
    document.body.style.transition = 'opacity 0.5s ease-out';
    document.body.style.opacity = '0';
    setTimeout(() => {
        window.location.href = '/';
    }, 500);
}

function goBack() {
    if (window.history.length > 1) {
        window.history.back();
    } else {
        goHome();
    }
}