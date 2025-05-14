// src/pages/Scan.jsx
import React, { useState } from 'react';
import { startScan } from '../services/apiService';

const Scan = () => {
  const [scanResults, setScanResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleScan = async () => {
    setIsLoading(true);
    try {
      const results = await startScan();
      setScanResults(results);
    } catch (error) {
      console.error('Scan failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold">Scan Your Network</h1>
      <button
        onClick={handleScan}
        className="bg-blue-500 text-white px-4 py-2 rounded mt-4"
        disabled={isLoading}
      >
        {isLoading ? 'Scanning...' : 'Start Scan'}
      </button>

      {scanResults && (
        <div className="mt-8">
          <h2 className="text-2xl">Scan Results</h2>
          <pre className="bg-gray-100 p-4 mt-4">{JSON.stringify(scanResults, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

export default Scan;
