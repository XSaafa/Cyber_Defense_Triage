function SeverityBadge({ severity }) {
  const colors = {
    critical: 'bg-red-500 text-white',
    high: 'bg-orange-400 text-gray-900',
    medium: 'bg-yellow-400 text-gray-900',
    low: 'bg-green-400 text-gray-900'
  }

  const icons = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢'
  }

  return (
    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-bold ${colors[severity]}`}>
      <span className="mr-1">{icons[severity]}</span>
      {severity.toUpperCase()}
    </span>
  )
}

export default SeverityBadge
