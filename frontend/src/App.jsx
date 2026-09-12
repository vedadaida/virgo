import React, { useState, useEffect, useCallback } from 'react';
import Landing from './pages/Landing.jsx';
import Dashboard from './pages/Dashboard.jsx';

export default function App() {
  const [page, setPage] = useState('landing');
  const [repos, setRepos] = useState([]);
  const [selectedRepoId, setSelectedRepoId] = useState('all');
  const [findings, setFindings] = useState([]);
  const [selectedFindingId, setSelectedFindingId] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanMeta, setScanMeta] = useState({
    lastScanTime: '—',
    systemOnline: true,
    filesAnalyzed: 1,
    lastSyncLabel: 'JUST NOW'
  });

  // 1. Fetch Repositories
  const fetchRepos = useCallback(async () => {
    try {
      const res = await fetch('/api/repos');
      if (res.ok) {
        const data = await res.json();
        setRepos(data);
      }
    } catch (err) {
      console.error('Failed to fetch repos:', err);
    }
  }, []);

  // 2. Fetch Findings
  const fetchFindings = useCallback(async (repoId = 'all') => {
    try {
      const endpoint = repoId && repoId !== 'all' 
        ? `/api/repos/${repoId}/findings`
        : '/api/findings';
      const res = await fetch(endpoint);
      if (res.ok) {
        const data = await res.json();
        setFindings(data);
        if (data.length > 0) {
          setSelectedFindingId(prev => (prev && data.some(f => f.id === prev) ? prev : data[0].id));
        } else {
          setSelectedFindingId(null);
        }
      }
    } catch (err) {
      console.error('Failed to fetch findings:', err);
    }
  }, []);

  useEffect(() => {
    if (page === 'dashboard') {
      fetchRepos();
      fetchFindings(selectedRepoId);
    }
  }, [page, selectedRepoId, fetchRepos, fetchFindings]);

  // 3. Trigger Scan
  const handleTriggerScan = async () => {
    try {
      setScanning(true);
      const activeRepo = repos.find(r => r.id === selectedRepoId);
      const repoName = activeRepo ? activeRepo.name : 'OWASP/NodeGoat-Local';

      const triggerRes = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoName,
          targetFile: 'vulnerable.js'
        })
      });

      if (!triggerRes.ok) throw new Error('Scan trigger failed');
      const { scanId } = await triggerRes.json();

      // Poll until finished
      const interval = setInterval(async () => {
        try {
          const statusRes = await fetch(`/api/scans/${scanId}`);
          if (statusRes.ok) {
            const scanData = await statusRes.json();
            if (scanData.status === 'COMPLETED' || scanData.status === 'FAILED') {
              clearInterval(interval);
              setScanning(false);
              const now = new Date().toTimeString().split(' ')[0];
              setScanMeta(prev => ({
                ...prev,
                lastScanTime: now,
                lastSyncLabel: '00:01 AGO'
              }));
              await fetchRepos();
              await fetchFindings(selectedRepoId);
            }
          }
        } catch (pollErr) {
          console.error('Poll error:', pollErr);
          clearInterval(interval);
          setScanning(false);
        }
      }, 1500);

    } catch (err) {
      console.error('Failed to trigger scan:', err);
      setScanning(false);
    }
  };

  // 4. Submit Feedback
  const handleFeedback = async (findingId, vote) => {
    try {
      // Optimistic update
      setFindings(prev => prev.map(f => f.id === findingId ? { ...f, feedback: vote } : f));

      await fetch(`/api/findings/${findingId}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vote })
      });
    } catch (err) {
      console.error('Feedback error:', err);
    }
  };

  const selectedRepoObj = repos.find(r => r.id === selectedRepoId);
  const surfaceTitle = selectedRepoId === 'all' ? 'ALL SURFACES' : (selectedRepoObj ? selectedRepoObj.name : 'REPOSITORY');

  if (page === 'landing') {
    return <Landing onEnter={() => setPage('dashboard')} />;
  }

  return (
    <Dashboard
      repos={repos}
      selectedRepoId={selectedRepoId}
      onSelectRepo={(id) => setSelectedRepoId(id)}
      scanMeta={scanMeta}
      onTriggerScan={handleTriggerScan}
      scanning={scanning}
      surfaceTitle={surfaceTitle}
      findings={findings}
      selectedFindingId={selectedFindingId}
      onSelectFinding={(id) => setSelectedFindingId(id)}
      onFeedback={handleFeedback}
      onClose={() => setPage('landing')}
    />
  );
}
