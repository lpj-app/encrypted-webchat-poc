import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const ASSET_EXTENSIONS = [
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico',
];

export function middleware(request: NextRequest) {
    const url = request.nextUrl;

    // Get hostname from request headers
    const hostname = request.headers.get('host') || '';

    const pathname = url.pathname;

    // Skip middleware for static assets under 'public' by extension or known paths
    const isStaticAsset =
        pathname.startsWith('/_next/static') ||
        pathname.startsWith('/_next/image') ||
        pathname === '/favicon.ico' ||
        pathname === '/sitemap.xml' ||
        pathname === '/robots.txt' ||
        ASSET_EXTENSIONS.some(ext => pathname.toLowerCase().endsWith(ext));

    if (isStaticAsset) {
        return NextResponse.next();
    }


    // Clean the hostname: remove port numbers and 'www.'
    const currentHost = hostname.split(':')[0].replace('www.', '');

    // -----------------------------------------------------------
    // 0. SECURITY CHECK (HOST HEADER VALIDATION)
    // -----------------------------------------------------------
    const allowedDomains = [
        '<your-domain>',
        'localhost',
    ];

    const isAllowedHost =
        allowedDomains.includes(currentHost) ||
        currentHost.endsWith('.<your-domain>');

    if (!isAllowedHost) {
        return new NextResponse('Bad Host Header', { status: 400 });
    }

    // 3. DEFAULT
    return NextResponse.next();
}

export const config = {
    matcher: [
        '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
    ],
};