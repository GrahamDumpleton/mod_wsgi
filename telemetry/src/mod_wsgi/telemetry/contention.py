"""GIL contention coefficient computation.

When a Python thread blocks waiting for the GIL, its wait time clusters
at multiples of ``sys.setswitchinterval`` (default 5 ms): a head bucket
below 1 ms for immediate handoffs, then bumps near s, 2*s, 3*s, ... — one
extra switch-interval cycle per missed handoff. Under fair contention
the per-cycle handoff success probability `q` is roughly constant and
the bump heights follow a geometric distribution::

    P(k cycles) = (1 - q) ** k * q

Fitting `q` from aggregated HDR-bucket counts yields a single contention
coefficient that is more interpretable than p95 / p99 of GIL-wait time:
high `q` means waits typically resolve in one handoff, low `q` means
threads consistently lose multiple cycles (convoy).

The wire format reports the active switch-interval value as field 13;
the consumer bands the aggregated GIL-wait HDR buckets at multiples of
that interval and fits the geometric on `c1..c3`. The k=0 (immediate)
band is intentionally excluded from the fit because it is contaminated
by voluntary GIL releases (I/O drops where the holder happens to release
before its check fires); these have nothing to do with contention but
inflate the head bucket.
"""

from __future__ import annotations

import math
from typing import Iterable


def cycle_band_counts(
    buckets: list[int],
    bucket_bounds: list[tuple[float, float]],
    switch_interval_s: float,
) -> list[int]:
    """Sum HDR bucket counts into cycle bands.

    Bands are indexed by k (cycles waited):
      k=0:    [0, 0.8*s)        immediate / voluntary release
      k=1:    [0.8*s, 1.8*s)    one missed handoff
      k=2:    [1.8*s, 2.8*s)    two missed handoffs
      k=3:    [2.8*s, 3.8*s)
      k=4plus: [3.8*s, inf)     tail (likely OS stalls, not race losses)

    A bucket is assigned to whichever band contains its midpoint. The
    head bucket (index 0) is treated as covering ``[0, bounds[0][1])``
    regardless of the lower edge passed in — the HDR helper used for
    percentile interpolation reports the head bucket's lower bound as
    the bottom of the first octave (1 ms), but for band assignment the
    head bucket logically starts at zero.

    Returns a 5-element list [c0, c1, c2, c3, c4plus].
    """
    s = switch_interval_s
    edges = [
        (0.0, 0.8 * s),
        (0.8 * s, 1.8 * s),
        (1.8 * s, 2.8 * s),
        (2.8 * s, 3.8 * s),
        (3.8 * s, math.inf),
    ]
    bands = [0] * 5
    for i, (count, (lo, hi)) in enumerate(zip(buckets, bucket_bounds)):
        if count <= 0:
            continue
        if i == 0:
            lo = 0.0
        if math.isinf(hi):
            mid = lo
        else:
            mid = 0.5 * (lo + hi)
        for k, (blo, bhi) in enumerate(edges):
            if blo <= mid < bhi:
                bands[k] += count
                break
    return bands


def _fit_geometric_decay(
    points: list[tuple[float, float, float]],
) -> dict | None:
    """Weighted log-linear fit of log(c[k]) vs k.

    ``points`` is a list of ``(x, log(count), weight)`` triples. Returns
    ``{"q": float, "r2": float}`` when the fit meets the geometric-decay
    assumption (negative slope, valid q in (0, 1), R² ≥ 0.5); returns
    ``None`` otherwise.
    """
    if len(points) < 2:
        return None

    sum_w = sum(p[2] for p in points)
    mean_x = sum(w * x for x, _, w in points) / sum_w
    mean_y = sum(w * y for _, y, w in points) / sum_w
    var_x = sum(w * (x - mean_x) ** 2 for x, _, w in points) / sum_w
    cov_xy = sum(
        w * (x - mean_x) * (y - mean_y) for x, y, w in points
    ) / sum_w

    if var_x <= 0.0:
        return None

    slope = cov_xy / var_x
    if slope >= 0.0:
        return None

    q = 1.0 - math.exp(slope)
    if not (0.0 < q < 1.0):
        return None

    intercept = mean_y - slope * mean_x
    ss_res = sum(
        w * (y - (intercept + slope * x)) ** 2 for x, y, w in points
    )
    var_y = sum(w * (y - mean_y) ** 2 for _, y, w in points)
    if var_y <= 0.0:
        return None
    r2 = 1.0 - ss_res / var_y

    if r2 < 0.5:
        return None

    return {"q": q, "r2": r2}


def contention_coefficient(
    buckets: list[int],
    bucket_bounds: list[tuple[float, float]],
    switch_interval_s: float,
) -> dict | None:
    """Compute the GIL contention coefficient from aggregated HDR buckets.

    Primary path fits a geometric decay to cycle bands ``c1..c3``.
    Fallback path fits ``c2..c4plus`` when ``c1`` is contaminated by the
    HDR head bucket — at switch intervals ≲ 1 ms the head bucket
    (1.25 ms wide on the default HDR config) absorbs both ``k=0``
    (immediate) and ``k=1`` (one missed cycle), leaving ``c1`` holding
    only the spillover. The contamination signature is ``c1 < c2``.

    Returns ``None`` if the data does not support a meaningful fit:
      - switch_interval not positive
      - fewer than 100 events in the chosen cycle bands combined
      - geometric fit R² below 0.5 (model doesn't apply, e.g. non-
        stationary load, very low contention, or extreme contamination)

    Otherwise returns a dict::

        {
          "q":            float,  # per-cycle handoff success probability
          "r":            float,  # 1 - q, convoy persistence
          "band_counts":  [c0, c1, c2, c3, c4plus],
          "fit_r2":       float,  # R^2 of the log-linear fit
          "n_total":      int,    # total events across all bands
          "n_fit":        int,    # events used in the fit
          "fit_kind":     str,    # "primary" or "fallback_c2_c4plus"
        }
    """
    if switch_interval_s <= 0.0:
        return None

    bands = cycle_band_counts(buckets, bucket_bounds, switch_interval_s)
    n_total = sum(bands)

    c1_contaminated = bands[1] < bands[2]

    if not c1_contaminated:
        n_fit = bands[1] + bands[2] + bands[3]
        if n_fit >= 100:
            points = [
                (float(k - 1), math.log(bands[k]), float(bands[k]))
                for k in (1, 2, 3)
                if bands[k] > 0
            ]
            fit = _fit_geometric_decay(points)
            if fit is not None:
                return {
                    "q": fit["q"],
                    "r": 1.0 - fit["q"],
                    "band_counts": bands,
                    "fit_r2": fit["r2"],
                    "n_total": n_total,
                    "n_fit": n_fit,
                    "fit_kind": "primary",
                }

    # Fallback: c2, c3, c4plus. c4plus aggregates the true k=4 cycle
    # band with the OS-stall tail beyond it, so the fit is somewhat
    # noisier and biased high in q (tail inflates c4plus); the R²
    # check still applies. Only attempted when c1 is contaminated —
    # the primary fit is preferred whenever it can run.
    n_fit = bands[2] + bands[3] + bands[4]
    if n_fit < 100:
        return None
    points = [
        (float(k - 2), math.log(bands[k]), float(bands[k]))
        for k in (2, 3, 4)
        if bands[k] > 0
    ]
    fit = _fit_geometric_decay(points)
    if fit is None:
        return None
    return {
        "q": fit["q"],
        "r": 1.0 - fit["q"],
        "band_counts": bands,
        "fit_r2": fit["r2"],
        "n_total": n_total,
        "n_fit": n_fit,
        "fit_kind": "fallback_c2_c4plus",
    }


def decay_label(q: float) -> str:
    """Verbal tier for q describing convoy-decay shape, NOT severity.

    ``q`` is the per-cycle handoff success probability fitted from the
    geometric decay across cycle bands; high ``q`` means convoys clear
    quickly (a missed cycle rarely chains into more), low ``q`` means
    they persist (the Beazley convoy signature). Whether ``q`` maps to
    "things are bad" depends on the absolute wall-clock cost per cycle
    (the switch interval) and the ``gil_wait_time`` mean — combine the
    two for a severity read.
    """
    if q >= 0.7:
        return "transient"
    if q >= 0.4:
        return "compounding"
    return "convoy"
