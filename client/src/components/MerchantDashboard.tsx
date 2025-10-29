import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  DollarSign,
  Users,
  TrendingUp,
  AlertCircle,
  Activity,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useQuery } from "@tanstack/react-query";

export function MerchantDashboard() {
  const { data: overview, isLoading: overviewLoading } = useQuery<any>({ queryKey: ['/api/analytics/overview'] });
  const { data: seriesData } = useQuery<any>({ queryKey: ['/api/analytics/revenue-timeseries'] });
  const { data: recent } = useQuery<any>({ queryKey: ['/api/analytics/recent-subscriptions'] });

  const metrics = [
    {
      title: 'Monthly Recurring Revenue',
      value: overview ? `$${(overview as any).mrr_usd?.toLocaleString?.() ?? (overview as any).mrr_usd ?? overview}` : overviewLoading ? 'Loading…' : 'No data',
      change: '+',
      icon: DollarSign,
      trend: 'up',
    },
    {
      title: 'Active Subscriptions',
      value: overview ? String((overview as any).active_subscriptions ?? (overview as any).active_subscriptions) : '—',
      change: '+',
      icon: Users,
      trend: 'up',
    },
    {
      title: 'Retention Rate',
      value: overview ? `${(overview as any).retention_rate_percent ?? (overview as any).retention_rate_percent}%` : '—',
      change: '+',
      icon: TrendingUp,
      trend: 'up',
    },
    {
      title: 'Failed Payments',
      value: overview ? String((overview as any).failed_payments_30d ?? (overview as any).failed_payments_30d) : '—',
      change: '-',
      icon: AlertCircle,
      trend: 'down',
    },
  ];

  const chartData = seriesData && (seriesData as any).timeseries
    ? (seriesData as any).timeseries.map((t: any) => ({ month: t.month, revenue: t.revenue }))
    : [];

  const recentSubs = recent && (recent as any).subscriptions
    ? (recent as any).subscriptions.map((s: any, idx: number) => ({
        id: s.subscription_id,
        customer: s.customer || `wallet_${String(idx).padStart(4, '0')}`,
        amount: `$${(Math.round((s.amount_usd || 0) * 100) / 100).toFixed(2)}`,
        interval: s.interval,
        status: s.status,
        nextPayment: s.next_payment ? new Date(s.next_payment).toISOString().split('T')[0] : '-',
      }))
    : [];

  return (
    <div className="relative">
      {/* Background (blurred & faded) */}
      <div className="opacity-30 pointer-events-none select-none">
        <div className="space-y-8">
          <div>
            <h2 className="text-3xl font-bold mb-2">Merchant Dashboard</h2>
            <p className="text-muted-foreground">Overview of your subscription business metrics</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {metrics.map((metric, index) => (
              <Card key={index} className="p-6 transition-all">
                <div className="flex items-center justify-between mb-4">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                    <metric.icon className="w-5 h-5 text-primary" />
                  </div>
                  <Badge className={metric.trend === 'up'
                    ? 'bg-chart-3/20 text-chart-3 border-chart-3/30'
                    : 'bg-chart-4/20 text-chart-4 border-chart-4/30'}>
                    {metric.change}
                  </Badge>
                </div>
                <h3 className="text-2xl font-bold mb-1">{metric.value}</h3>
                <p className="text-sm text-muted-foreground">{metric.title}</p>
              </Card>
            ))}
          </div>

          <Card className="p-8">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-xl font-bold">Revenue Trend</h3>
                <p className="text-sm text-muted-foreground">Monthly recurring revenue over time</p>
              </div>
              <Activity className="w-5 h-5 text-muted-foreground" />
            </div>
            <div className="h-80">
              {chartData.length === 0 ? (
                <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                  {overviewLoading ? 'Loading chart…' : 'No revenue data available'}
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="colorRevenue" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" opacity={0.1} />
                    <XAxis dataKey="month" />
                    <YAxis />
                    <Tooltip />
                    <Area type="monotone" dataKey="revenue" stroke="hsl(var(--primary))" fillOpacity={1} fill="url(#colorRevenue)" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </Card>
        </div>
      </div>

      {/* Overlay: COMING SOON */}
      <div className="absolute inset-0 flex items-center justify-center bg-background/60 backdrop-blur-sm">
        <h1 className="text-6xl md:text-8xl font-extrabold text-primary/90 drop-shadow-lg uppercase tracking-widest animate-pulse">
          Coming Soon!
        </h1>
      </div>
    </div>
  );
}
