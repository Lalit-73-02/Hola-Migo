import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import './index.css'
import { initializeDemoData } from './utils/demoData.ts'

// Initialize demo data
initializeDemoData();

createRoot(document.getElementById("root")!).render(<App />);
