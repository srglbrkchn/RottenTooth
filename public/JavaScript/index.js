
document.querySelector('.mailbox-btn').addEventListener('click', function(){
  document.querySelector('.mailbox-content').classList.toggle('visible');
  document.querySelector('.general-btn').classList.toggle('invisible');
});

function thisYear(){
  const today = new Date();
  const year = today.getFullYear();
  document.querySelector('.year').innerHTML = year;
}
