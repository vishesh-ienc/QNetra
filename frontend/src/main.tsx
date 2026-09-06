import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { API_MODE } from './api/client';
import { ScanProvider } from './state/ScanContext';
import { App } from './App';
import './styles/base.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        const status = (error as { status?: number }).status;
        if (status && status >= 400 && status < 500) return false;
        return failureCount < 2;
      },
    },
  },
});

/**
 * The fixture transport is loaded only in mock mode, so a live build never pulls
 * the offline dataset into the bundle.
 */
async function boot(): Promise<void> {
  if (API_MODE === 'mock') {
    const { installMockTransport } = await import('./mocks/transport');
    installMockTransport();
  }

  createRoot(document.getElementById('root') as HTMLElement).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <ScanProvider>
            <App />
          </ScanProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </StrictMode>,
  );
}

void boot();
