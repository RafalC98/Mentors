let startNr = 0;
const endMenNr = 120;
const endMeetNr = 580;
const endUsersNr = 230;

document.querySelector("#mentorsCounter").innerHTML = startNr;
document.querySelector("#meetingsCounter").innerHTML = startNr;
document.querySelector("#activeUsersCounter").innerHTML = startNr;

const countUp = (counter, count, endNr) => {
  if (count < endNr) {
    setTimeout(() => {
      count++;
      document.querySelector(counter).innerHTML = count;
      countUp(counter, count, endNr);
    }, 1);
  }
};

document.addEventListener("DOMContentLoaded", () =>
  countUp("#mentorsCounter", startNr, endMenNr)
);
document.addEventListener("DOMContentLoaded", () =>
  countUp("#meetingsCounter", startNr, endMeetNr)
);
document.addEventListener("DOMContentLoaded", () =>
  countUp("#activeUsersCounter", startNr, endUsersNr)
);
