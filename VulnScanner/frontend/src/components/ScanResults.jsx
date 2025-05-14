import React from "react";

const ScanResults = ({ data }) => {
  if (!data) return <p className="text-gray-500">No scan data provided.</p>;

  const { host, scan_time, nikto_scans, services } = data;

  return (
    <div className="p-6 space-y-6">
      <div className="bg-white rounded-2xl shadow-md p-4">
        <h2 className="text-2xl font-bold text-gray-800">🔍 Scan Summary</h2>
        <p><strong>Host:</strong> {host}</p>
        <p><strong>Time:</strong> {new Date(scan_time).toLocaleString()}</p>
      </div>

      {/* SERVICES & CVEs */}
      <div className="bg-white rounded-2xl shadow-md p-4">
        <h2 className="text-xl font-semibold mb-4">📡 Services & CVEs</h2>
        {services.map((service, index) => (
          <div key={index} className="border-b border-gray-200 py-4">
            <p className="font-semibold text-blue-700">
              Port {service.port} — {service.service || "Unknown"}
            </p>
            <p className="text-sm text-gray-500 mb-2">
              {service.banner || "No banner"} | Version: {service.version || "N/A"}
            </p>
            {service.cves.length > 0 ? (
              <ul className="ml-4 list-disc space-y-1">
                {service.cves.map((cve, idx) => (
                  <li key={idx}>
                    <span className="font-semibold">{cve.id}</span>: {cve.description}
                    <span className={`ml-2 px-2 py-0.5 text-xs rounded-full ${
                      cve.severity === "CRITICAL"
                        ? "bg-red-600 text-white"
                        : cve.severity === "HIGH"
                        ? "bg-orange-500 text-white"
                        : "bg-gray-300 text-gray-800"
                    }`}>
                      {cve.severity || "Unknown"}
                    </span>
                    {cve.cvss && (
                      <span className="ml-2 text-sm text-gray-600">
                        (CVSS: {cve.cvss})
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-gray-400 ml-4">No CVEs found.</p>
            )}
          </div>
        ))}
      </div>

      {/* NIKTO RESULTS */}
      <div className="bg-white rounded-2xl shadow-md p-4">
        <h2 className="text-xl font-semibold mb-4">🛡️ Nikto Vulnerabilities</h2>
        {nikto_scans.map((scan, index) => (
          <div key={index} className="mb-4">
            <p className="font-semibold text-blue-700 mb-2">URL: {scan.url}</p>
            {scan.vulnerabilities[0]?.vulnerabilities.length > 0 ? (
              <ul className="ml-4 list-disc space-y-1">
                {scan.vulnerabilities[0].vulnerabilities.map((vuln, i) => (
                  <li key={i}>
                    <span className="font-semibold">[{vuln.id}]</span> {vuln.msg}
                    {vuln.references && (
                      <a
                        href={vuln.references}
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue-500 ml-2 underline text-sm"
                      >
                        ref
                      </a>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-gray-400 ml-4">No vulnerabilities reported.</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default ScanResults;
