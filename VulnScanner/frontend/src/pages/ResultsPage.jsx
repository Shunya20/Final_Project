import React, { useEffect, useState } from "react";
import ScanResults from "../components/ScanResults";
import axios from "axios";

const ResultsPage = () => {
  const [data, setData] = useState(null);

  useEffect(() => {
    axios.get("http://localhost:5000/api/scan-result") // 🔁 change this URL to your actual endpoint
      .then((res) => setData(res.data))
      .catch((err) => console.error(err));
  }, []);

  return (
    <div className="min-h-screen bg-gray-100 p-6">
      <ScanResults data={data} />
    </div>
  );
};

export default ResultsPage;
