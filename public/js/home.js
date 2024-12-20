document.addEventListener("DOMContentLoaded", () => {
  let csrfToken;

  // Fetch CSRF token and store it in a variable
  fetch("/csrf-token", {
    method: "GET",
    credentials: "include",
  })
    .then((response) => response.json())
    .then((data) => {
      csrfToken = data.csrfToken;
      console.log("CSRF token fetched:", csrfToken);
    })
    .catch((error) => {
      console.error("Error fetching CSRF token:", error);
    });

  // Function to refresh access token
  async function refreshAccessToken() {
    try {
      const response = await fetch("/refresh-token", {
        method: "POST",
        headers: {
          "CSRF-Token": csrfToken, // Include CSRF token in the request headers
        },
        credentials: "include",
      });

      if (!response.ok) {
        throw new Error("Failed to refresh access token");
      }

      const result = await response.json();
      console.log("Access token refreshed:", result.accessToken);
      if (!result.accessToken) {
        throw new Error("Access token is undefined");
      }
      startCountdown(result.accessToken); // Restart countdown with new access token
    } catch (error) {
      console.error("Error refreshing access token:", error);
      //window.location.href = "/login.html";
    }
  }

  // Function to start countdown timer
  function startCountdown(token) {
    try {
      if (!token) {
        throw new Error("Token is null or undefined");
      }

      console.log("Token before decoding:", token);
      const decodedToken = jwt_decode(token);
      console.log("Decoded token:", decodedToken);

      if (!decodedToken || !decodedToken.exp) {
        throw new Error("Invalid token");
      }

      const expirationTime = decodedToken.exp * 1000;
      const countdownElement = document.getElementById("countdown");

      function updateCountdown() {
        const currentTime = Date.now();
        const remainingTime = expirationTime - currentTime;

        if (remainingTime <= 0) {
          countdownElement.innerText = "Token expired";
          clearInterval(countdownInterval);
          window.alert("Your session has expired. Refreshing access token...");
          refreshAccessToken();
        } else {
          const minutes = Math.floor(remainingTime / 60000);
          const seconds = Math.floor((remainingTime % 60000) / 1000);
          countdownElement.innerText = `Token expires in ${minutes}m ${seconds}s`;
        }
      }

      updateCountdown();
      const countdownInterval = setInterval(updateCountdown, 1000);
    } catch (error) {
      console.error("Error decoding token:", error);
      //window.location.href = "/login.html";
    }
  }

  // Check authentication by making a request to a protected endpoint
  async function checkAuthentication() {
    try {
      const response = await fetch("/protected", {
        method: "GET",
        credentials: "include", // Include cookies in the request
      });

      if (response.status === 401) {
        window.alert("Your session has expired. Refreshing access token...");
        await refreshAccessToken();
        return checkAuthentication();
      }

      if (!response.ok) {
        throw new Error("Not authenticated");
      }

      const data = await response.json();
      console.log("Access token received:", data.accessToken);
      if (!data.accessToken) {
        throw new Error("Access token is undefined");
      }
      document.getElementById("welcome-message").innerText =
        "Welcome, authenticated user!";
      startCountdown(data.accessToken); // Start countdown with current access token
    } catch (error) {
      console.error("Error:", error);
      //window.location.href = "/login.html";
    }
  }

  // Extract access token from URL
  const urlParams = new URLSearchParams(window.location.search);
  const accessToken = urlParams.get("accessToken");
  if (accessToken) {
    console.log("Access token from URL:", accessToken);
    startCountdown(accessToken);
  } else {
    checkAuthentication();
  }

  // Logout function
  document.getElementById("logout-button").addEventListener("click", () => {
    fetch("/logout", {
      method: "POST",
      credentials: "include", // Include cookies in the request
      headers: {
        "CSRF-Token": csrfToken, // Include CSRF token in the request headers
      },
    })
      .then((response) => {
        if (response.ok) {
          window.location.href = "/login.html";
        } else {
          console.error("Logout failed");
        }
      })
      .catch((error) => {
        console.error("Error:", error);
      });
  });
});
