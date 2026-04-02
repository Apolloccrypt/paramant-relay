import WindstilMap from './WindstilMap'
import './App.css'

export default function App() {
  return (
    <div className="app">
      <header className="app-header">
        <div className="header-inner">
          <div className="logo">
            <span className="logo-icon">〜</span>
            <span className="logo-text">Windstil</span>
          </div>
          <div className="header-sub">Live windkaart Nederland</div>
        </div>
      </header>
      <main className="map-container">
        <WindstilMap />
      </main>
    </div>
  )
}
