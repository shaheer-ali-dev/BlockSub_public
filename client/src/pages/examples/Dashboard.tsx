import Dashboard from "../Dashboard";
import { ThemeProvider } from "@/components/ThemeProvider";

export default function DashboardExample() {
  return (
    <ThemeProvider>
      <Dashboard />
    </ThemeProvider>
  );
}
