import { useEffect, useState } from "react";

export const useTimer = (initialTime: number) => {
  const [time, setTime] = useState<number>(initialTime);

  useEffect(() => {
    const savedTime = localStorage.getItem("countdown-timer");
    if (savedTime) {
      const remainingTime = parseInt(savedTime, 10);
      setTime(remainingTime);
    }

    const interval = setInterval(() => {
      setTime((prevTime) => {
        if (prevTime <= 1) {
          clearInterval(interval);
          localStorage.removeItem("countdown-timer");
          return 0;
        }
        const newTime = prevTime - 1;
        localStorage.setItem("countdown-timer", newTime.toString());
        return newTime;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  return { time, setTime };
};
