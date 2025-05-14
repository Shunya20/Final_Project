// src/services/apiService.js
export const startScan = async () => {
    const response = await fetch('http://localhost:5000/api/start-scan');  // Adjust the URL as needed
    if (response.ok) {
      return await response.json();
    }
    throw new Error('Scan failed');
  };
  