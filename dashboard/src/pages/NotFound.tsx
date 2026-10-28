import { Link, useLocation } from "react-router-dom";
import { Header } from "../components/ui";

export default function NotFound() {
  const { pathname } = useLocation();
  return (
    <div className="page">
      <Header title="Page not found" sub={`There is no page at ${pathname}.`} />
      <p className="text-sm"><Link className="text-accent" to="/">Go to the overview</Link> · <Link className="text-accent" to="/intake">Intake</Link> · <Link className="text-accent" to="/graph">Lineage graph</Link></p>
    </div>
  );
}
