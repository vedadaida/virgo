import { useState } from 'react';
import './Landing.css';

const BOOT_STEPS = [
  'INITIALIZING VIRGO...',
  'LOADING REPOSITORY INDEX...',
  'ANALYZING SECURITY SURFACE...',
  'SYSTEM READY.'
];

// onEnter: called once the boot sequence finishes.
// Wire this to your router, e.g. onEnter={() => navigate('/dashboard')}
export default function Landing({ onEnter }) {
  const [booting, setBooting] = useState(false);
  const [visibleSteps, setVisibleSteps] = useState([]);
  const [barComplete, setBarComplete] = useState(false);

  const handleEnter = () => {
    setBooting(true);
    setVisibleSteps([]);
    setBarComplete(false);

    let i = 0;
    const showNext = () => {
      if (i < BOOT_STEPS.length) {
        setVisibleSteps(prev => [...prev, BOOT_STEPS[i]]);
        i++;
        setTimeout(showNext, 420);
      } else {
        setBarComplete(true);
        setTimeout(() => {
          onEnter && onEnter();
        }, 900);
      }
    };
    setTimeout(showNext, 200);
  };

  return (
    <div className="virgo-landing">
      <div className="stage">
        <div className="stars" />
        <div className="flares">
          <div className="flare f1" />
          <div className="flare f2" />
          <div className="flare f3" />
          <div className="flare f4" />
        </div>

        <div className="statusbar">
          <div className="status-left">
            <span className="sys">SYS://VIRGO</span>
            <span className="build">BUILD 1987.04</span>
          </div>
          <div className="status-right">
            <span className="online"><span className="ring" />ONLINE</span>
            <span>NODE 04</span>
          </div>
        </div>

        <div className="hero">
          <div className="eyebrow">/// SYSTEM ONLINE ///</div>
          <h1 className="title">VIRGO</h1>
          <div className="subtitle">SECURITY INTELLIGENCE SYSTEM</div>
          <div className="divider">
            <div className="diamond" /><div className="dash" />
            <div className="diamond" /><div className="dash" />
            <div className="diamond" />
          </div>
          <div className="actions">
            <button className="btn primary" onClick={handleEnter}>
              &#8594; ENTER VIRGO
            </button>
          </div>
        </div>

        <div className="footer">
          <span>REPOSITORY INTELLIGENCE // SECURITY ANALYSIS</span>
          <span>SIGNAL: STABLE</span>
        </div>
      </div>

      <div className={`boot-overlay${booting ? ' show' : ''}`}>
        <div className="boot-panel">
          <h3>&#9889; VIRGO // BOOT SEQUENCE</h3>
          <div>
            {visibleSteps.map((step, idx) => (
              <div className="boot-line done" key={idx}>
                <span className="arrow">&gt;</span>{step}
              </div>
            ))}
          </div>
          <div className="boot-bar-track">
            <div
              className="boot-bar-fill"
              style={{ width: barComplete ? '100%' : '0%' }}
            />
          </div>
          <div className="boot-status">
            {barComplete ? '0x54 // LINK ESTABLISHED' : '0x00 // ESTABLISHING LINK'}
          </div>
        </div>
      </div>
    </div>
  );
}
