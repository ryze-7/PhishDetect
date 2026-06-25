const currentDomain = window.location.hostname;

const forms = document.querySelectorAll('form');
const domFlags = [];

forms.forEach(form => {
    const hasPasswordField = form.querySelector('input[type="password"]');
    if (!hasPasswordField) return;

    const action = form.getAttribute('action');
    if (!action) return;

    try {
        const actionDomain = new URL(action, window.location.href).hostname;
        if (actionDomain && actionDomain !== currentDomain) {
            domFlags.push(`Form submits to different domain: ${actionDomain}`);
        }
    } catch {
        // invalid action URL, skip
    }
});

console.log('DOM flags:', domFlags);