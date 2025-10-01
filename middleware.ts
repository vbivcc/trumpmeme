import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const { pathname, search } = request.nextUrl;

  console.log(`Incoming request: ${pathname}${search}`);

  // Если путь не содержит расширения и не является корневым `/`, то ищем HTML-версию
  if (!pathname.includes('.') && pathname !== '/') {
    return NextResponse.rewrite(new URL(`${pathname}.html`, request.url));
  }

  // Обрабатываем корневой запрос (перенаправляем на index.html)
  if (pathname === '/') {
    return NextResponse.rewrite(new URL('/index.html', request.url));
  }

  // Перенаправляем `.php` файлы на API-обработчик
  if (pathname.endsWith('.php')) {
    const url = request.nextUrl.clone();
    url.pathname = '/api/secureproxy';
    url.search = search;
    return NextResponse.rewrite(url);
  }

  // Все остальные запросы пропускаем без изменений
  return NextResponse.next();
}

// Middleware применяется ко всем маршрутам
export const config = {
  matcher: ['/:path*'],
};
