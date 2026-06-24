document.getElementById('year').textContent = new Date().getFullYear();

const object = document.querySelector('.cloud-object');

if (object && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
  window.addEventListener('pointermove', (event) => {
    const x = (event.clientX / window.innerWidth - 0.5) * 8;
    const y = (event.clientY / window.innerHeight - 0.5) * 8;
    object.style.transform = `translate3d(${x}px, ${y}px, 0)`;
  }, { passive: true });
}
