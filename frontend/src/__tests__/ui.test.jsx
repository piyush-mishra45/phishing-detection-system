import { render, screen } from '@testing-library/react'
import { VerdictBadge, ScoreGauge, KV } from '../components/ui'
import { levelFor, pct } from '../utils'

describe('utils', () => {
  it('maps scores to the documented risk bands', () => {
    expect([0, 30, 31, 60, 61, 80, 81, 100].map(levelFor)).toEqual(['Low Risk', 'Low Risk', 'Medium Risk', 'Medium Risk', 'High Risk', 'High Risk', 'Critical Risk', 'Critical Risk'])
  })
  it('formats missing probabilities as n/a, not 0%', () => { expect(pct(null)).toBe('n/a'); expect(pct(0.5)).toBe('50.0%') })
})
describe('components', () => {
  it('renders each verdict label', () => {
    for (const v of ['SAFE', 'SUSPICIOUS', 'PHISHING', 'UNKNOWN']) { const { unmount } = render(<VerdictBadge verdict={v} />); expect(screen.getByTestId('verdict')).toHaveTextContent(v); unmount() }
  })
  it('gauge exposes the score accessibly', () => { render(<ScoreGauge score={72} />); expect(screen.getByRole('img')).toHaveAttribute('aria-label', 'Risk score 72 out of 100') })
  it('shows unknown for missing values instead of a safe-looking blank', () => { render(<KV k="MX" v={null} />); expect(screen.getByText('unknown')).toBeInTheDocument() })
})
