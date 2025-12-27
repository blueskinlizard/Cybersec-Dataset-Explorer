import { useState } from 'react';
import CICIDSVisualization from './visualization_components/CICIDSVis';
import UNSWVisualization from './visualization_components/UNSW_NB15Vis';

function App() {
  const [activeView, setActiveView] = useState(null);

  const containerStyle = {
    fontFamily: '"Inter", "Segoe UI", Roboto, sans-serif',
    backgroundColor: '#0f172a',
    color: '#f8fafc',
    width: '100vw',
    height: '100vh',
    margin: 0,
    padding: 0,
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden' 
  };

  const headerStyle = {
    textAlign: 'center',
    padding: '20px 0',
    background: 'linear-gradient(180deg, #1e293b 0%, #0f172a 100%)',
    borderBottom: '1px solid #334155'
  };

  const navStyle = {
    display: 'flex',
    justifyContent: 'center',
    gap: '15px',
    padding: '20px',
  };

  const buttonBaseStyle = {
    padding: '12px 24px',
    fontSize: '14px',
    fontWeight: '600',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'all 0.2s ease',
    border: '1px solid #334155',
    textTransform: 'uppercase',
    letterSpacing: '0.5px'
  };

  const activeButtonStyle = {
    ...buttonBaseStyle,
    backgroundColor: '#38bdf8',
    color: '#0f172a',
    borderColor: '#38bdf8',
    boxShadow: '0 0 15px rgba(56, 189, 248, 0.4)'
  };

  const inactiveButtonStyle = {
    ...buttonBaseStyle,
    backgroundColor: '#1e293b',
    color: '#94a3b8',
  };

  const contentStyle = {
    flex: 1,
    padding: '20px',
    overflowY: 'auto', 
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center'
  };

  const placeholderStyle = {
    marginTop: '10vh',
    textAlign: 'center',
    color: '#64748b',
    border: '2px dashed #334155',
    padding: '40px',
    borderRadius: '12px',
    maxWidth: '500px'
  };

  return (
    <div style={containerStyle}>
      <header style={headerStyle}>
        <h1 style={{ fontSize: '1.8rem', margin: '0 0 5px 0', color: '#f1f5f9' }}>
          Network analysis menu
        </h1>
        <p style={{ color: '#94a3b8', margin: 0, fontSize: '0.9rem' }}>
          Select a dataset (UNSW/CICIDS) to view visualization(s) on
        </p>
      </header>

      <nav style={navStyle}>
        <button 
          style={activeView === 'CICIDS' ? activeButtonStyle : inactiveButtonStyle}
          onClick={() => setActiveView('CICIDS')}>
          Initialize CIC-IDS 2017
        </button>
        <button 
          style={activeView === 'UNSW' ? activeButtonStyle : inactiveButtonStyle}
          onClick={() => setActiveView('UNSW')}>
          Initialize UNSW-NB15
        </button>
        
        {activeView && (
          <button 
            style={{...buttonBaseStyle, backgroundColor: 'transparent', color: '#ef4444', borderColor: '#ef4444'}}
            onClick={() => setActiveView(null)}>
            Clear Canvas
          </button>
        )}
      </nav>

      <main style={contentStyle}>
        {!activeView ? (
          <div style={placeholderStyle}>
            <svg 
              width="48" height="48" viewBox="0 0 24 24" fill="none" 
              stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"
              style={{ marginBottom: '20px', opacity: 0.5 }}
            >
              <path d="M21 12V7H5a2 2 0 0 1 0-4h14v4" />
              <path d="M3 5v14a2 2 0 0 0 2 2h16v-5" />
              <path d="M18 12a2 2 0 0 0 0 4h4v-4Z" />
            </svg>
            <p style={{ margin: 0 }}>Program Running. Waiting for dataset selection...</p>
          </div>
        ) : (
          <div style={{ width: '100%', maxWidth: '1400px' }}>
            {activeView === 'CICIDS' && <CICIDSVisualization />}
            {activeView === 'UNSW' && <UNSWVisualization />}
          </div>
        )}
      </main>
    </div>
  );
}

export default App;