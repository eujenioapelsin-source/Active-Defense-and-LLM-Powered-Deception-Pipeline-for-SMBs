import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const API_BASE = process.env.API_BASE_URL ?? 'http://api:8000';
const CONSOLE_TOKEN = process.env.AEGIS_CONSOLE_TOKEN ?? '';

export async function POST(request: NextRequest) {
  if (!CONSOLE_TOKEN) {
    return NextResponse.json({ error: 'Service not configured' }, { status: 503 });
  }
  try {
    const body = await request.json();
    const upstream = await fetch(`${API_BASE}/seal`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${CONSOLE_TOKEN}`,
      },
      body: JSON.stringify(body),
      cache: 'no-store',
    });
    const data = await upstream.json();
    return NextResponse.json(data, { status: upstream.status });
  } catch (error) {
    return NextResponse.json({ error: 'Upstream unavailable' }, { status: 502 });
  }
}