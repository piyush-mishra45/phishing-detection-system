import { useCallback, useEffect, useState } from 'react'
import { errMsg } from '../services/api'

/** Runs an async loader on mount / when deps change. Returns {data, loading, error, reload}. */
export function useAsync(fn, deps = []) {
  const [state, set] = useState({ data: null, loading: true, error: '' })
  const run = useCallback(() => {
    set((s) => ({ ...s, loading: true, error: '' }))
    let alive = true
    fn().then((data) => alive && set({ data, loading: false, error: '' })).catch((e) => alive && set({ data: null, loading: false, error: errMsg(e) }))
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => run(), [run])
  return { ...state, reload: run }
}
