document.querySelectorAll('[data-toggle]').forEach((button) => {
  button.addEventListener('click', () => {
    const input = document.getElementById(button.dataset.toggle);
    const showing = input.type === 'password';
    input.type = showing ? 'text' : 'password';
    button.textContent = showing ? 'Hide' : 'Show';
    button.setAttribute('aria-label', `${showing ? 'Hide' : 'Show'} ${input.id === 'confirm_password' ? 'confirmation password' : 'password'}`);
    button.setAttribute('aria-pressed', String(showing));
  });
});

const confirmation = document.getElementById('confirm_password');
const password = document.getElementById('password');
if (confirmation && password) {
  const validate = () => confirmation.setCustomValidity(
    confirmation.value && confirmation.value !== password.value ? 'Your passwords don’t match.' : ''
  );
  confirmation.addEventListener('input', validate);
  password.addEventListener('input', validate);
}

const paymentForm = document.querySelector('[data-payment-form]');
if (paymentForm) {
  paymentForm.addEventListener('submit', () => {
    paymentForm.querySelector('[role="status"]').hidden = false;
  });
  window.addEventListener('pageshow', () => {
    paymentForm.querySelector('[role="status"]').hidden = true;
  });
}
