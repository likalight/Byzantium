import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Sidebar }  from './components/Sidebar';
import { Overview } from './pages/Overview';
import { Agents }   from './pages/Agents';
import { TrustLog } from './pages/TrustLog';
import { ApiKeys }  from './pages/ApiKeys';
import { Billing }  from './pages/Billing';
import { Health }   from './pages/Health';

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-bg">
        <Sidebar />
        <main className="flex-1 flex flex-col">
          <Routes>
            <Route path="/"        element={<Overview />} />
            <Route path="/agents"  element={<Agents />}   />
            <Route path="/log"     element={<TrustLog />} />
            <Route path="/keys"    element={<ApiKeys />}  />
            <Route path="/billing" element={<Billing />}  />
            <Route path="/health"  element={<Health />}   />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
