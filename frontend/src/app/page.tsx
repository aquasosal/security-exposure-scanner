'use client';

import { useState } from 'react';

type Finding = {
  file_path: string;
  file_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  url: string;
  http_status?: number;
  content_preview?: string;
  risk_description?: string;
  remediation?: string;
};

type ScanProgress = {
  scan_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  total_files_checked: number;
  total_findings: number;
  findings_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
};

export default function Home() {
  const [targetUrl, setTargetUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'low':
        return 'bg-blue-100 text-blue-800 border-blue-300';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return '🔴 Critical';
      case 'high':
        return '🟠 High';
      case 'medium':
        return '🟡 Medium';
      case 'low':
        return '🔵 Low';
      default:
        return '⚪ Info';
    }
  };

  const handleScan = async () => {
    if (!targetUrl) {
      alert('URL을 입력해주세요');
      return;
    }

    setIsScanning(true);
    setProgress(null);
    setFindings([]);

    try {
      const response = await fetch('/api/v1/scans/execute', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_url: targetUrl,
          scan_config: {
            depth: 1,
            wordlists: ['sensitive-files.txt', 'config-files.txt', 'env-files.txt', 'git-files.txt'],
            timeout: 30,
            concurrent: 10,
          },
        }),
      });

      if (!response.ok) {
        throw new Error('스캔 실패');
      }

      const data = await response.json();
      setFindings(data.findings || []);

      if (progress) {
        setProgress({
          ...progress,
          status: 'completed',
          progress: 100,
          total_findings: data.total_findings || 0,
        });
      }

      alert(`스캔 완료! ${data.total_findings || 0}개의 민감한 파일 발견`);
    } catch (error) {
      console.error('Scan error:', error);
      alert('스캔 중 오류가 발생했습니다');
      if (progress) {
        setProgress({
          ...progress,
          status: 'failed',
        });
      }
    } finally {
      setIsScanning(false);
    }
  };

  const filteredFindings =
    selectedSeverity === 'all'
      ? findings
      : findings.filter((f) => f.severity === selectedSeverity);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <header className="mb-8 text-center">
          <h1 className="text-4xl font-bold text-white mb-2">
            🛡️ Security Exposure Scanner
          </h1>
          <p className="text-slate-400 text-lg">
            노출된 개발 파일 및 설정 파일을 자동으로 감지합니다
          </p>
        </header>

        {/* Scan Input */}
        <div className="max-w-3xl mx-auto mb-8">
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 shadow-2xl border border-slate-700">
            <div className="flex gap-4">
              <input
                type="url"
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isScanning}
                className="flex-1 px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-50"
              />
              <button
                onClick={handleScan}
                disabled={isScanning || !targetUrl}
                className="px-8 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isScanning ? '스캔 중...' : '🔍 스캔 시작'}
              </button>
            </div>

            {/* Progress Bar */}
            {progress && progress.status === 'running' && (
              <div className="mt-4">
                <div className="flex justify-between text-sm text-slate-400 mb-2">
                  <span>{progress.progress}% 완료</span>
                  <span>{progress.total_files_checked}개 파일 검사</span>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${progress.progress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Stats */}
            {progress && (progress.status === 'completed' || progress.status === 'running') && (
              <div className="grid grid-cols-4 gap-4 mt-4">
                <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                  <div className="text-3xl font-bold text-white">
                    {progress.findings_by_severity?.critical || 0}
                  </div>
                  <div className="text-sm text-red-400">Critical</div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                  <div className="text-3xl font-bold text-white">
                    {progress.findings_by_severity?.high || 0}
                  </div>
                  <div className="text-sm text-orange-400">High</div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                  <div className="text-3xl font-bold text-white">
                    {progress.findings_by_severity?.medium || 0}
                  </div>
                  <div className="text-sm text-yellow-400">Medium</div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                  <div className="text-3xl font-bold text-white">
                    {progress.findings_by_severity?.low || 0}
                  </div>
                  <div className="text-sm text-blue-400">Low</div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Findings Table */}
        {findings.length > 0 && (
          <div className="max-w-7xl mx-auto">
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl shadow-2xl border border-slate-700 overflow-hidden">
              {/* Filter */}
              <div className="p-4 border-b border-slate-700">
                <div className="flex gap-2">
                  {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setSelectedSeverity(sev)}
                      className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                        selectedSeverity === sev
                          ? 'bg-blue-600 text-white'
                          : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                      }`}
                    >
                      {sev === 'all' ? '전체' : sev.charAt(0).toUpperCase() + sev.slice(1)}
                      {sev !== 'all' && ` (${progress?.findings_by_severity?.[sev as keyof typeof progress.findings_by_severity] || 0})`}
                    </button>
                  ))}
                </div>
              </div>

              {/* Table */}
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-slate-900/50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        파일 경로
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        심각도
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        HTTP 상태
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        위험 설명
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        조치 방법
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {filteredFindings.map((finding, index) => (
                      <tr
                        key={index}
                        className="hover:bg-slate-700/50 transition-colors"
                      >
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-2">
                            <span className="text-slate-300 font-mono text-sm">
                              {finding.file_path}
                            </span>
                            <a
                              href={finding.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-400 hover:text-blue-300 text-xs"
                            >
                              🔗
                            </a>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`px-3 py-1 rounded-full text-xs font-medium border ${getSeverityColor(finding.severity)}`}
                          >
                            {getSeverityBadge(finding.severity)}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          {finding.http_status ? (
                            <span
                              className={`font-mono text-sm ${
                                finding.http_status === 200
                                  ? 'text-green-400'
                                  : 'text-yellow-400'
                              }`}
                            >
                              {finding.http_status}
                            </span>
                          ) : (
                            <span className="text-slate-500">-</span>
                          )}
                        </td>
                        <td className="px-6 py-4">
                          <p className="text-slate-300 text-sm max-w-md">
                            {finding.risk_description || '민감한 파일 노출'}
                          </p>
                        </td>
                        <td className="px-6 py-4">
                          <p className="text-slate-300 text-sm max-w-md">
                            {finding.remediation || '파일 삭제 및 배포 파이프라인 확인'}
                          </p>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Empty State */}
              {filteredFindings.length === 0 && (
                <div className="py-12 text-center text-slate-400">
                  표시할 결과가 없습니다
                </div>
              )}
            </div>
          </div>
        )}

        {/* Footer */}
        <footer className="mt-12 text-center text-slate-500 text-sm">
          <p>🔒 Security Exposure Scanner - 민감한 파일 노출 감지</p>
          <p className="mt-1">
            GitHub:{' '}
            <a
              href="https://github.com/aquasosal/security-exposure-scanner"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:text-blue-300"
            >
              aquasosal/security-exposure-scanner
            </a>
          </p>
        </footer>
      </div>
    </div>
  );
}
