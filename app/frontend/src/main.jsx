import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { AppProvider } from "./lib/AppContext.jsx";
import { IconSprite } from "./components/Icon.jsx";
import { TipProvider } from "./components/Tip.jsx";
import "./app.css";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <AppProvider>
      <TipProvider>
        <IconSprite />
        <App />
      </TipProvider>
    </AppProvider>
  </StrictMode>
);
