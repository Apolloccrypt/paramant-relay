import { useEffect, useState, useRef } from 'react'

const NL_STATIONS = [
  { id: 'de-bilt',      name: 'De Bilt',      lat: 52.10, lon: 5.18 },
  { id: 'amsterdam',    name: 'Amsterdam',    lat: 52.37, lon: 4.90 },
  { id: 'rotterdam',    name: 'Rotterdam',    lat: 51.92, lon: 4.48 },
  { id: 'den-haag',     name: 'Den Haag',     lat: 52.07, lon: 4.32 },
  { id: 'utrecht',      name: 'Utrecht',      lat: 52.09, lon: 5.12 },
  { id: 'eindhoven',    name: 'Eindhoven',    lat: 51.44, lon: 5.48 },
  { id: 'groningen',    name: 'Groningen',    lat: 53.22, lon: 6.57 },
  { id: 'maastricht',   name: 'Maastricht',   lat: 50.85, lon: 5.69 },
  { id: 'leeuwarden',   name: 'Leeuwarden',   lat: 53.20, lon: 5.80 },
  { id: 'zwolle',       name: 'Zwolle',       lat: 52.52, lon: 6.10 },
  { id: 'arnhem',       name: 'Arnhem',       lat: 51.98, lon: 5.91 },
  { id: 'vlissingen',   name: 'Vlissingen',   lat: 51.45, lon: 3.57 },
  { id: 'lelystad',     name: 'Lelystad',     lat: 52.52, lon: 5.47 },
  { id: 'enschede',     name: 'Enschede',     lat: 52.22, lon: 6.90 },
  { id: 'breda',        name: 'Breda',        lat: 51.59, lon: 4.78 },
]

// Bounding box Nederland
const NL_BOUNDS = { latMin: 50.75, latMax: 53.55, lonMin: 3.36, lonMax: 7.22 }

function latLonToXY(lat, lon, width, height) {
  const x = ((lon - NL_BOUNDS.lonMin) / (NL_BOUNDS.lonMax - NL_BOUNDS.lonMin)) * width
  const y = ((NL_BOUNDS.latMax - lat) / (NL_BOUNDS.latMax - NL_BOUNDS.latMin)) * height
  return { x, y }
}

function windSpeedColor(speed) {
  if (speed === null || speed === undefined) return '#333'
  if (speed < 3)  return '#2e86ab'   // windstil / zwak
  if (speed < 7)  return '#44cf6c'   // matig
  if (speed < 12) return '#f4d03f'   // stevig
  if (speed < 18) return '#f39c12'   // hard
  return '#e74c3c'                    // storm
}

function WindArrow({ x, y, speed, direction }) {
  if (speed === null || direction === null) return null
  const len = Math.min(8 + speed * 1.4, 32)
  const rad = (direction * Math.PI) / 180
  const dx = Math.sin(rad) * len
  const dy = -Math.cos(rad) * len
  const color = windSpeedColor(speed)

  // pijlpunt
  const headLen = 6
  const angle = Math.atan2(dy, dx)
  const ax1 = x + dx - headLen * Math.cos(angle - 0.4)
  const ay1 = y + dy - headLen * Math.sin(angle - 0.4)
  const ax2 = x + dx - headLen * Math.cos(angle + 0.4)
  const ay2 = y + dy - headLen * Math.sin(angle + 0.4)

  return (
    <g>
      <line x1={x} y1={y} x2={x + dx} y2={y + dy} stroke={color} strokeWidth={2} strokeLinecap="round" />
      <polyline points={`${ax1},${ay1} ${x + dx},${y + dy} ${ax2},${ay2}`} stroke={color} strokeWidth={2} fill="none" strokeLinejoin="round" />
    </g>
  )
}

function StationDot({ x, y, station, wind, onClick, selected }) {
  const speed = wind?.windspeed_10m
  const color = windSpeedColor(speed)
  return (
    <g style={{ cursor: 'pointer' }} onClick={() => onClick(station, wind)}>
      <circle cx={x} cy={y} r={selected ? 9 : 7} fill={color} stroke={selected ? '#fff' : '#111'} strokeWidth={selected ? 2 : 1} opacity={0.92} />
      {wind && <WindArrow x={x} y={y} speed={speed} direction={wind.winddirection_10m} />}
    </g>
  )
}

function Legend() {
  const items = [
    { label: '< 3 m/s  Windstil', color: '#2e86ab' },
    { label: '3–7 m/s  Matig', color: '#44cf6c' },
    { label: '7–12 m/s  Stevig', color: '#f4d03f' },
    { label: '12–18 m/s  Hard', color: '#f39c12' },
    { label: '> 18 m/s  Storm', color: '#e74c3c' },
  ]
  return (
    <div style={{ position: 'absolute', bottom: 16, left: 16, background: 'rgba(15,15,15,0.88)', borderRadius: 8, padding: '10px 14px', border: '1px solid #2a2a2a' }}>
      {items.map(i => (
        <div key={i.label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, fontSize: 12, color: '#ccc' }}>
          <div style={{ width: 12, height: 12, borderRadius: '50%', background: i.color, flexShrink: 0 }} />
          {i.label}
        </div>
      ))}
    </div>
  )
}

export default function WindstilMap() {
  const [windData, setWindData] = useState({})
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [lastUpdate, setLastUpdate] = useState(null)
  const svgRef = useRef(null)
  const [svgSize, setSvgSize] = useState({ w: 500, h: 600 })

  useEffect(() => {
    const updateSize = () => {
      if (svgRef.current) {
        const rect = svgRef.current.getBoundingClientRect()
        setSvgSize({ w: rect.width || 500, h: rect.height || 600 })
      }
    }
    updateSize()
    window.addEventListener('resize', updateSize)
    return () => window.removeEventListener('resize', updateSize)
  }, [])

  useEffect(() => {
    async function fetchWind() {
      setLoading(true)
      try {
        // Open-Meteo API — gratis, geen API key nodig
        const lats = NL_STATIONS.map(s => s.lat).join(',')
        const lons = NL_STATIONS.map(s => s.lon).join(',')
        const url = `https://api.open-meteo.com/v1/forecast?latitude=${lats}&longitude=${lons}&current=windspeed_10m,winddirection_10m,windgusts_10m&wind_speed_unit=ms&timezone=Europe%2FAmsterdam`
        const res = await fetch(url)
        const json = await res.json()
        const data = {}
        const results = Array.isArray(json) ? json : [json]
        results.forEach((r, i) => {
          data[NL_STATIONS[i].id] = {
            windspeed_10m:    r.current?.windspeed_10m ?? null,
            winddirection_10m: r.current?.winddirection_10m ?? null,
            windgusts_10m:    r.current?.windgusts_10m ?? null,
          }
        })
        setWindData(data)
        setLastUpdate(new Date())
      } catch (e) {
        console.error('Wind data ophalen mislukt:', e)
      }
      setLoading(false)
    }
    fetchWind()
    const interval = setInterval(fetchWind, 5 * 60 * 1000) // elke 5 minuten
    return () => clearInterval(interval)
  }, [])

  const { w, h } = svgSize

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>
      <svg
        ref={svgRef}
        width="100%"
        height="100%"
        style={{ display: 'block' }}
        onClick={e => { if (e.target === svgRef.current) setSelected(null) }}
      >
        {/* Achtergrond */}
        <rect width={w} height={h} fill="#0f0f0f" />

        {/* Grid */}
        {[...Array(8)].map((_, i) => (
          <line key={`vg${i}`} x1={(i / 7) * w} y1={0} x2={(i / 7) * w} y2={h} stroke="#1a1a1a" strokeWidth={1} />
        ))}
        {[...Array(8)].map((_, i) => (
          <line key={`hg${i}`} x1={0} y1={(i / 7) * h} x2={w} y2={(i / 7) * h} stroke="#1a1a1a" strokeWidth={1} />
        ))}

        {/* Stations */}
        {NL_STATIONS.map(station => {
          const { x, y } = latLonToXY(station.lat, station.lon, w, h)
          const wind = windData[station.id]
          return (
            <StationDot
              key={station.id}
              x={x} y={y}
              station={station}
              wind={wind}
              selected={selected?.station.id === station.id}
              onClick={(s, w) => setSelected({ station: s, wind: w, x, y })}
            />
          )
        })}

        {/* Labels */}
        {NL_STATIONS.map(station => {
          const { x, y } = latLonToXY(station.lat, station.lon, w, h)
          return (
            <text key={`lbl-${station.id}`} x={x + 11} y={y + 4} fontSize={10} fill="#888" style={{ pointerEvents: 'none', userSelect: 'none' }}>
              {station.name}
            </text>
          )
        })}

        {/* Popup */}
        {selected && (() => {
          const px = Math.min(selected.x + 14, w - 170)
          const py = Math.max(selected.y - 10, 10)
          const { station, wind } = selected
          return (
            <g>
              <rect x={px} y={py} width={155} height={90} rx={8} fill="#181818" stroke="#333" strokeWidth={1} />
              <text x={px + 10} y={py + 20} fontSize={13} fontWeight="600" fill="#eee">{station.name}</text>
              {wind ? (
                <>
                  <text x={px + 10} y={py + 40} fontSize={11} fill="#aaa">Wind: {wind.windspeed_10m?.toFixed(1) ?? '–'} m/s</text>
                  <text x={px + 10} y={py + 56} fontSize={11} fill="#aaa">Richting: {wind.winddirection_10m ?? '–'}°</text>
                  <text x={px + 10} y={py + 72} fontSize={11} fill="#aaa">Gusts: {wind.windgusts_10m?.toFixed(1) ?? '–'} m/s</text>
                </>
              ) : (
                <text x={px + 10} y={py + 40} fontSize={11} fill="#666">Geen data</text>
              )}
            </g>
          )
        })()}

        {/* Loading overlay */}
        {loading && (
          <g>
            <rect width={w} height={h} fill="rgba(0,0,0,0.5)" />
            <text x={w / 2} y={h / 2} textAnchor="middle" fontSize={14} fill="#888">Winddata ophalen…</text>
          </g>
        )}
      </svg>

      <Legend />

      {lastUpdate && (
        <div style={{ position: 'absolute', top: 12, right: 12, fontSize: 11, color: '#555', background: 'rgba(0,0,0,0.6)', padding: '4px 8px', borderRadius: 4 }}>
          Bijgewerkt: {lastUpdate.toLocaleTimeString('nl-NL')}
        </div>
      )}
    </div>
  )
}
