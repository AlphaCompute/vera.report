import { useState, useEffect } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import { Coins, TrendingUp, Users, Lock, Rocket, Vote, Target, Flame } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Badge, Button } from '@/components/ui';
import Navbar from '@/components/Navbar';

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  RadialLinearScale,
  Filler
} from 'chart.js';
import { Doughnut, Bar, Line, Radar } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Filler,
  Title,
  Tooltip,
  Legend
);


export default function Tokenomics() {
  const router = useRouter();
  const [selectedTab, setSelectedTab] = useState('overview');
  const [isMobile, setIsMobile] = useState(false);

  // Handle URL section parameter
  useEffect(() => {
    const section = router.query.section as string;
    if (section && ['overview', 'rewards', 'staking', 'roadmap'].includes(section)) {
      setSelectedTab(section);
    }
  }, [router.query.section]);

  // Update URL when tab changes
  const handleTabChange = (tab: string) => {
    setSelectedTab(tab);
    router.push(`/tokenomics?section=${tab}`, undefined, { shallow: true });
  };

  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Set dark mode
  useEffect(() => {
    document.documentElement.classList.add('dark');
  }, []);

  const tokenDistributionData = {
    labels: ['ASI', 'NIGHT', 'TON'],
    datasets: [{
      label: 'Token Distribution',
      data: [40, 40, 20],
      backgroundColor: [
        'rgba(147, 51, 234, 0.8)',
        'rgba(59, 130, 246, 0.8)',
        'rgba(96, 165, 250, 0.8)'
      ],
      borderColor: [
        'rgba(147, 51, 234, 1)',
        'rgba(59, 130, 246, 1)',
        'rgba(96, 165, 250, 1)'
      ],
      borderWidth: 2
    }]
  };

  const revenueAllocationData = {
    labels: ['Buyback & Burn', 'Development', 'Staking Rewards', 'Marketing', 'Team'],
    datasets: [{
      label: 'Revenue Allocation',
      data: [40, 25, 20, 10, 5],
      backgroundColor: [
        'rgba(129, 140, 248, 0.8)',
        'rgba(59, 130, 246, 0.8)',
        'rgba(96, 165, 250, 0.8)',
        'rgba(167, 139, 250, 0.8)',
        'rgba(147, 51, 234, 0.8)'
      ],
      borderWidth: 2
    }]
  };

  const stakingTiersData = {
    labels: ['Bronze', 'Silver', 'Gold', 'Platinum'],
    datasets: [{
      label: 'Reward Multiplier',
      data: [1.1, 1.25, 1.5, 2.0],
      backgroundColor: 'rgba(107, 97, 255, 0.2)',
      borderColor: 'rgba(107, 97, 255, 1)',
      borderWidth: 2,
      fill: true
    }]
  };

  const projectedGrowthData = {
    labels: ['Month 1', 'Month 3', 'Month 6', 'Month 9', 'Month 12'],
    datasets: [
      {
        label: 'Users (thousands)',
        data: [10, 35, 100, 180, 300],
        borderColor: 'rgb(59, 130, 246)',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        yAxisID: 'y',
        fill: true
      },
      {
        label: 'TVL ($ millions)',
        data: [0.5, 2, 5, 8, 10],
        borderColor: 'rgb(167, 139, 250)',
        backgroundColor: 'rgba(167, 139, 250, 0.1)',
        yAxisID: 'y1',
        fill: true
      }
    ]
  };

  const tierComparisonData = {
    labels: ['Daily Cap ($)', 'Message Limit', 'Multiplier', 'ASI %', 'NIGHT %', 'TON %'],
    datasets: [
      {
        label: 'Basic User',
        data: [10, 100, 1, 40, 40, 20],
        backgroundColor: 'rgba(59, 130, 246, 0.2)',
        borderColor: 'rgb(59, 130, 246)',
        pointBackgroundColor: 'rgb(59, 130, 246)',
      },
      {
        label: 'Active User',
        data: [25, 500, 1.5, 35, 45, 20],
        backgroundColor: 'rgba(167, 139, 250, 0.2)',
        borderColor: 'rgb(167, 139, 250)',
        pointBackgroundColor: 'rgb(167, 139, 250)',
      },
      {
        label: 'Power User',
        data: [50, 1000, 2, 30, 50, 20],
        backgroundColor: 'rgba(107, 97, 255, 0.2)',
        borderColor: 'rgb(107, 97, 255)',
        pointBackgroundColor: 'rgb(107, 97, 255)',
      }
    ]
  };

  const rewardRates = [
    { action: 'AI Agent Message', asi: 0.001, night: 0, ton: 0 },
    { action: 'P2P Encrypted Message', asi: 0, night: 0.0001, ton: 0 },
    { action: 'Model Training Data', asi: 0.01, night: 0, ton: 0 },
    { action: 'ZK Proof Generation', asi: 0, night: 0.0005, ton: 0 },
    { action: 'Cross-Chain Bridge', asi: 0, night: 0, ton: 0.0002 },
    { action: 'Referral Success', asi: 0, night: 0, ton: 0.1 }
  ];

  const stakingTiers = [
    { tier: 'Bronze', requirement: '100-1,000 NIGHT', multiplier: '1.1x', apy: '+5%' },
    { tier: 'Silver', requirement: '1,000-10,000 NIGHT', multiplier: '1.25x', apy: '+10%' },
    { tier: 'Gold', requirement: '10,000-50,000 NIGHT', multiplier: '1.5x', apy: '+20%' },
    { tier: 'Platinum', requirement: '50,000+ NIGHT', multiplier: '2.0x', apy: '+35%' }
  ];

  const implementationPhases = [
    { phase: 'Genesis', months: '1-3', features: 'Basic rewards, NIGHT staking, Anti-gaming' },
    { phase: 'Growth', months: '4-6', features: 'ASI integration, TON payments, Governance' },
    { phase: 'Maturity', months: '7-12', features: 'Full tokenomics, Cross-chain, Enterprise' },
    { phase: 'Expansion', months: '12+', features: 'Multi-chain, DeFi, Global scaling' }
  ];

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: !isMobile,
    plugins: {
      legend: {
        labels: {
          color: 'rgba(243, 244, 248, 0.9)',
          font: { size: isMobile ? 11 : 13 }
        }
      }
    }
  };

  const lineChartOptions = {
    responsive: true,
    maintainAspectRatio: !isMobile,
    interaction: {
      mode: 'index' as const,
      intersect: false,
    },
    scales: {
      y: {
        type: 'linear' as const,
        display: true,
        position: 'left' as const,
        ticks: { color: 'rgba(243, 244, 248, 0.7)' },
        grid: { color: 'rgba(243, 244, 248, 0.1)' }
      },
      y1: {
        type: 'linear' as const,
        display: true,
        position: 'right' as const,
        ticks: { color: 'rgba(243, 244, 248, 0.7)' },
        grid: { drawOnChartArea: false },
      },
      x: {
        ticks: { color: 'rgba(243, 244, 248, 0.7)' },
        grid: { color: 'rgba(243, 244, 248, 0.1)' }
      }
    },
    plugins: {
      legend: {
        labels: {
          color: 'rgba(243, 244, 248, 0.9)',
          font: { size: isMobile ? 11 : 13 }
        }
      }
    }
  };

  const barChartOptions = {
    responsive: true,
    maintainAspectRatio: !isMobile,
    scales: {
      y: {
        beginAtZero: true,
        ticks: { color: 'rgba(243, 244, 248, 0.7)' },
        grid: { color: 'rgba(243, 244, 248, 0.1)' }
      },
      x: {
        ticks: { color: 'rgba(243, 244, 248, 0.7)' },
        grid: { color: 'rgba(243, 244, 248, 0.1)' }
      }
    },
    plugins: {
      legend: { display: false }
    }
  };

  const radarChartOptions = {
    responsive: true,
    maintainAspectRatio: !isMobile,
    scales: {
      r: {
        angleLines: { color: 'rgba(243, 244, 248, 0.1)' },
        grid: { color: 'rgba(243, 244, 248, 0.1)' },
        pointLabels: {
          color: 'rgba(243, 244, 248, 0.9)',
          font: { size: isMobile ? 9 : 11 }
        },
        ticks: { color: 'rgba(243, 244, 248, 0.7)', backdropColor: 'transparent' }
      }
    },
    plugins: {
      legend: {
        labels: {
          color: 'rgba(243, 244, 248, 0.9)',
          font: { size: isMobile ? 11 : 13 }
        }
      }
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Coins },
    { id: 'rewards', label: 'Rewards', icon: TrendingUp },
    { id: 'staking', label: 'Staking', icon: Lock },
    { id: 'roadmap', label: 'Roadmap', icon: Rocket }
  ];

  return (
    <>
      <Head>
        <title>Tokenomics | Vera</title>
        <meta name="description" content="Triple-token reward ecosystem for encrypted communications" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      </Head>

      {/* Navbar */}
      <Navbar
        onTokenomicsTabChange={handleTabChange}
        currentTokenomicsTab={selectedTab}
      />

      <div className="min-h-screen text-foreground pt-16" style={{
        overflowX: 'hidden',
        WebkitOverflowScrolling: 'touch'
      }}>
        <div className="fixed inset-0 -z-10 overflow-hidden pointer-events-none">
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/10 rounded-full blur-[100px] -translate-y-1/2 translate-x-1/4" />
          <div className="absolute bottom-0 left-0 w-[400px] h-[400px] bg-chart-1/10 rounded-full blur-[100px] translate-y-1/2 -translate-x-1/4" />
        </div>

        <div className={`mx-auto ${isMobile ? 'px-4 py-8 pb-24' : 'max-w-7xl px-6 py-12'}`}>

          {/* Header */}
          <div className={`text-center ${isMobile ? 'mb-8' : 'mb-12'}`}>
            <div className="flex items-center justify-center gap-3 mb-4">
              <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                <Coins className="w-6 h-6 text-primary" />
              </div>
            </div>
            <h1 className={`font-bold mb-4 gradient-text ${isMobile ? 'text-3xl' : 'text-5xl'}`}>
              Vera Tokenomics
            </h1>
            <p className={`text-muted-foreground max-w-2xl mx-auto ${isMobile ? 'text-base px-2' : 'text-lg'}`}>
              Earn rewards for secure, encrypted communications across three powerful blockchain ecosystems
            </p>
          </div>

          {/* Tab Navigation */}
          <div className={`flex justify-center ${isMobile ? 'mb-8' : 'mb-10'}`}>
            {isMobile ? (
              <div className="grid grid-cols-2 gap-2 w-full max-w-sm">
                {tabs.map(tab => (
                  <Button
                    key={tab.id}
                    onClick={() => handleTabChange(tab.id)}
                    variant={selectedTab === tab.id ? 'default' : 'outline'}
                    className={`flex items-center justify-center gap-2 h-11 ${
                      selectedTab === tab.id ? '' : 'bg-card/50'
                    }`}
                  >
                    <tab.icon className="w-4 h-4" />
                    <span className="text-sm font-medium">{tab.label}</span>
                  </Button>
                ))}
              </div>
            ) : (
              <div className="bg-card/50 backdrop-blur-lg rounded-full p-1.5 flex gap-1 border border-border">
                {tabs.map(tab => (
                  <Button
                    key={tab.id}
                    onClick={() => handleTabChange(tab.id)}
                    variant={selectedTab === tab.id ? 'default' : 'ghost'}
                    className={`rounded-full flex items-center gap-2 px-5 ${
                      selectedTab === tab.id ? '' : 'text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    <tab.icon className="w-4 h-4" />
                    {tab.label}
                  </Button>
                ))}
              </div>
            )}
          </div>

          {/* Content */}
          {selectedTab === 'overview' && (
            <div className={`${isMobile ? 'space-y-6' : 'space-y-8'}`}>

              {/* Charts Grid */}
              <div className={`grid gap-6 ${isMobile ? 'grid-cols-1' : 'md:grid-cols-2'}`}>
                <Card className="bg-card/50 backdrop-blur-lg border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className={`text-foreground ${isMobile ? 'text-lg' : 'text-xl'}`}>Token Distribution</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className={`${isMobile ? 'h-56' : 'h-72'} flex items-center justify-center`}>
                      <div className="w-full max-w-xs">
                        <Doughnut data={tokenDistributionData} options={chartOptions} />
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-card/50 backdrop-blur-lg border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className={`text-foreground ${isMobile ? 'text-lg' : 'text-xl'}`}>Revenue Allocation</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className={`${isMobile ? 'h-56' : 'h-72'} flex items-center justify-center`}>
                      <div className="w-full max-w-xs">
                        <Doughnut data={revenueAllocationData} options={chartOptions} />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Growth Chart */}
              <Card className="bg-card/50 backdrop-blur-lg border-border">
                <CardHeader className="pb-2">
                  <CardTitle className={`text-foreground flex items-center gap-2 ${isMobile ? 'text-lg' : 'text-xl'}`}>
                    <TrendingUp className="w-5 h-5 text-chart-1" />
                    Projected Growth
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className={isMobile ? 'h-64' : 'h-80'}>
                    <Line data={projectedGrowthData} options={lineChartOptions} />
                  </div>
                </CardContent>
              </Card>

              {/* Token Cards */}
              <div className={`grid gap-4 ${isMobile ? 'grid-cols-1' : 'md:grid-cols-3'}`}>
                <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/20">
                  <CardContent className={`${isMobile ? 'p-5' : 'p-6'}`}>
                    <Badge className="text-purple-400 bg-purple-500/10 border-purple-500/30 mb-3">ASI TOKEN</Badge>
                    <h3 className={`font-bold mb-2 text-foreground ${isMobile ? 'text-xl' : 'text-2xl'}`}>AI Rewards</h3>
                    <p className="text-muted-foreground text-sm">Earn for AI agent interactions and data contributions</p>
                  </CardContent>
                </Card>

                <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
                  <CardContent className={`${isMobile ? 'p-5' : 'p-6'}`}>
                    <Badge className="text-blue-400 bg-blue-500/10 border-blue-500/30 mb-3">NIGHT TOKEN</Badge>
                    <h3 className={`font-bold mb-2 text-foreground ${isMobile ? 'text-xl' : 'text-2xl'}`}>Privacy Power</h3>
                    <p className="text-muted-foreground text-sm">Core network utility and zero-knowledge operations</p>
                  </CardContent>
                </Card>

                <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
                  <CardContent className={`${isMobile ? 'p-5' : 'p-6'}`}>
                    <Badge className="text-blue-400 bg-blue-500/10 border-blue-500/30 mb-3">TON TOKEN</Badge>
                    <h3 className={`font-bold mb-2 text-foreground ${isMobile ? 'text-xl' : 'text-2xl'}`}>Cross-Chain</h3>
                    <p className="text-muted-foreground text-sm">Bridge operations and instant micropayments</p>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}

          {selectedTab === 'rewards' && (
            <div className={`${isMobile ? 'space-y-6' : 'space-y-8'}`}>

              {/* Tier Comparison - Desktop only */}
              {!isMobile && (
                <Card className="bg-card/50 backdrop-blur-lg border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-foreground text-xl flex items-center gap-2">
                      <Users className="w-5 h-5 text-blue-400" />
                      User Tier Comparison
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="h-80">
                      <Radar data={tierComparisonData} options={radarChartOptions} />
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Reward Rates Table */}
              <Card className={`bg-card/50 backdrop-blur-lg border-border ${isMobile ? 'overflow-x-auto' : ''}`}>
                <CardHeader className="pb-2">
                  <CardTitle className={`text-foreground flex items-center gap-2 ${isMobile ? 'text-lg' : 'text-xl'}`}>
                    <Coins className="w-5 h-5 text-violet-400" />
                    Reward Rates
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className={isMobile ? 'min-w-[480px]' : ''}>
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-border">
                          <th className="text-left py-3 px-3 text-muted-foreground font-medium text-sm">Action</th>
                          <th className="text-center py-3 px-3 text-muted-foreground font-medium text-sm">ASI</th>
                          <th className="text-center py-3 px-3 text-muted-foreground font-medium text-sm">NIGHT</th>
                          <th className="text-center py-3 px-3 text-muted-foreground font-medium text-sm">TON</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rewardRates.map((rate, index) => (
                          <tr key={index} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                            <td className="py-3 px-3 text-foreground text-sm">{rate.action}</td>
                            <td className="text-center py-3 px-3 text-sm">
                              {rate.asi > 0 ? <span className="text-purple-400 font-medium">{rate.asi}</span> : <span className="text-muted-foreground">-</span>}
                            </td>
                            <td className="text-center py-3 px-3 text-sm">
                              {rate.night > 0 ? <span className="text-blue-400 font-medium">{rate.night}</span> : <span className="text-muted-foreground">-</span>}
                            </td>
                            <td className="text-center py-3 px-3 text-sm">
                              {rate.ton > 0 ? <span className="text-blue-400 font-medium">{rate.ton}</span> : <span className="text-muted-foreground">-</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>

              {/* User Tier Cards */}
              <div className={`grid gap-4 ${isMobile ? 'grid-cols-1' : 'md:grid-cols-3'}`}>
                <Card className="bg-card/50 backdrop-blur-lg border-border">
                  <CardContent className={`${isMobile ? 'p-5' : 'p-6'}`}>
                    <div className="flex items-center justify-between mb-4">
                      <h4 className="font-semibold text-foreground text-lg">Basic User</h4>
                      <Badge variant="secondary">Tier 1</Badge>
                    </div>
                    <ul className="space-y-3 text-sm">
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Daily Messages:</span>
                        <span className="text-foreground font-medium">0-100</span>
                      </li>
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Multiplier:</span>
                        <span className="text-foreground font-medium">1x</span>
                      </li>
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Daily Cap:</span>
                        <span className="text-foreground font-medium">$10</span>
                      </li>
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Token Mix:</span>
                        <span className="text-foreground font-medium">40/40/20</span>
                      </li>
                    </ul>
                  </CardContent>
                </Card>

                <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
                  <CardContent className={`${isMobile ? 'p-5' : 'p-6'}`}>
                    <div className="flex items-center justify-between mb-4">
                      <h4 className="font-semibold text-foreground text-lg">Active User</h4>
                      <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">Tier 2</Badge>
                    </div>
                    <ul className="space-y-3 text-sm">
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Daily Messages:</span>
                        <span className="text-foreground font-medium">100-500</span>
                      </li>
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Multiplier:</span>
                        <span className="text-blue-400 font-medium">1.5x</span>
                      </li>
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Daily Cap:</span>
                        <span className="text-foreground font-medium">$25</span>
                      </li>
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Token Mix:</span>
                        <span className="text-foreground font-medium">35/45/20</span>
                      </li>
                    </ul>
                  </CardContent>
                </Card>

                <Card className="bg-gradient-to-br from-primary/10 to-primary/5 border-primary/20">
                  <CardContent className={`${isMobile ? 'p-5' : 'p-6'}`}>
                    <div className="flex items-center justify-between mb-4">
                      <h4 className="font-semibold text-foreground text-lg">Power User</h4>
                      <Badge className="bg-primary/20 text-primary border-primary/30">Tier 3</Badge>
                    </div>
                    <ul className="space-y-3 text-sm">
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Daily Messages:</span>
                        <span className="text-foreground font-medium">500+</span>
                      </li>
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Multiplier:</span>
                        <span className="text-primary font-medium">2x</span>
                      </li>
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Daily Cap:</span>
                        <span className="text-foreground font-medium">$50</span>
                      </li>
                      <li className="flex justify-between">
                        <span className="text-muted-foreground">Token Mix:</span>
                        <span className="text-foreground font-medium">30/50/20</span>
                      </li>
                    </ul>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}

          {selectedTab === 'staking' && (
            <div className={`${isMobile ? 'space-y-6' : 'space-y-8'}`}>

              {/* Staking Chart */}
              <Card className="bg-card/50 backdrop-blur-lg border-border">
                <CardHeader className="pb-2">
                  <CardTitle className={`text-foreground flex items-center gap-2 ${isMobile ? 'text-lg' : 'text-xl'}`}>
                    <Lock className="w-5 h-5 text-primary" />
                    Staking Tier Multipliers
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className={isMobile ? 'h-56' : 'h-72'}>
                    <Bar data={stakingTiersData} options={barChartOptions} />
                  </div>
                </CardContent>
              </Card>

              {/* Staking Tiers */}
              <Card className="bg-card/50 backdrop-blur-lg border-border">
                <CardHeader className="pb-2">
                  <CardTitle className={`text-foreground ${isMobile ? 'text-lg' : 'text-xl'}`}>Staking Tiers</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className={`grid gap-4 ${isMobile ? 'grid-cols-1' : 'md:grid-cols-2'}`}>
                    {stakingTiers.map((tier, index) => (
                      <div key={index} className="bg-muted/30 rounded-xl border border-border p-4">
                        <div className="flex justify-between items-start mb-3">
                          <h4 className="font-semibold text-primary text-lg">{tier.tier}</h4>
                          <span className="font-bold text-chart-1 text-2xl">{tier.multiplier}</span>
                        </div>
                        <p className="text-muted-foreground text-sm mb-3">{tier.requirement}</p>
                        <div className="flex justify-between items-center pt-3 border-t border-border/50">
                          <span className="text-muted-foreground text-sm">Lock-up APY:</span>
                          <span className="font-semibold text-foreground">{tier.apy}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Lock-up and Deflationary */}
              <div className={`grid gap-6 ${isMobile ? 'grid-cols-1' : 'md:grid-cols-2'}`}>
                <Card className="bg-card/50 backdrop-blur-lg border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className={`text-foreground flex items-center gap-2 ${isMobile ? 'text-lg' : 'text-xl'}`}>
                      <Lock className="w-5 h-5 text-blue-400" />
                      Lock-up Bonuses
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {[
                        { period: '30 Days', bonus: '+5% APY' },
                        { period: '90 Days', bonus: '+10% APY' },
                        { period: '180 Days', bonus: '+20% APY' },
                        { period: '365 Days', bonus: '+35% APY' }
                      ].map((item, index) => (
                        <div key={index} className="flex justify-between items-center bg-muted/30 rounded-lg p-3">
                          <span className="text-foreground text-sm">{item.period}</span>
                          <span className="text-chart-1 font-semibold text-sm">{item.bonus}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-card/50 backdrop-blur-lg border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className={`text-foreground flex items-center gap-2 ${isMobile ? 'text-lg' : 'text-xl'}`}>
                      <Flame className="w-5 h-5 text-destructive" />
                      Deflationary Mechanisms
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {[
                        { title: 'Quarterly Burns', desc: '5% of revenue for buyback & burn' },
                        { title: 'Transaction Burns', desc: '0.01% of every transaction' },
                        { title: 'Inactivity Penalty', desc: '1% monthly after 180 days inactive' }
                      ].map((item, index) => (
                        <div key={index} className="bg-destructive/10 border border-destructive/20 rounded-lg p-3">
                          <div className="text-destructive font-semibold text-sm">{item.title}</div>
                          <div className="text-muted-foreground text-xs mt-1">{item.desc}</div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}

          {selectedTab === 'roadmap' && (
            <div className={`${isMobile ? 'space-y-6' : 'space-y-8'}`}>

              {/* Implementation Roadmap */}
              <Card className="bg-card/50 backdrop-blur-lg border-border">
                <CardHeader className="pb-2">
                  <CardTitle className={`text-foreground flex items-center gap-2 ${isMobile ? 'text-lg' : 'text-xl'}`}>
                    <Rocket className="w-5 h-5 text-primary" />
                    Implementation Roadmap
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    {implementationPhases.map((phase, index) => (
                      <div key={index} className="relative">
                        <div className="flex items-start gap-4">
                          <div className={`flex-shrink-0 bg-primary rounded-full flex items-center justify-center font-bold text-primary-foreground ${
                            isMobile ? 'w-10 h-10 text-sm' : 'w-12 h-12'
                          }`}>
                            {index + 1}
                          </div>
                          <div className="flex-grow">
                            <div className="bg-muted/30 rounded-xl p-4">
                              <div className="flex flex-wrap justify-between items-start gap-2 mb-2">
                                <h4 className="font-semibold text-primary text-lg">{phase.phase}</h4>
                                <Badge variant="outline" className="text-muted-foreground">Months {phase.months}</Badge>
                              </div>
                              <p className="text-muted-foreground text-sm">{phase.features}</p>
                            </div>
                          </div>
                        </div>
                        {index < implementationPhases.length - 1 && (
                          <div className={`absolute bg-primary/30 ${
                            isMobile ? 'left-5 top-12 bottom-0 w-0.5 -mb-2' : 'left-6 top-14 bottom-0 w-0.5 -mb-2'
                          }`} style={{ height: '24px' }}></div>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* KPIs and Governance */}
              <div className={`grid gap-6 ${isMobile ? 'grid-cols-1' : 'md:grid-cols-2'}`}>
                <Card className="bg-card/50 backdrop-blur-lg border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className={`text-foreground flex items-center gap-2 ${isMobile ? 'text-lg' : 'text-xl'}`}>
                      <Target className="w-5 h-5 text-chart-1" />
                      Key Performance Indicators
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-1">
                      {[
                        { label: 'Target Users (6 months)', value: '100,000' },
                        { label: 'TVL Target (Year 1)', value: '$10M' },
                        { label: 'Staking Rate', value: '50%' },
                        { label: 'Monthly Volatility', value: '<10%' },
                        { label: 'User Retention', value: '80%' }
                      ].map((item, index) => (
                        <li key={index} className="flex justify-between py-3 border-b border-border/50 last:border-0">
                          <span className="text-muted-foreground text-sm">{item.label}</span>
                          <span className="text-foreground font-semibold text-sm">{item.value}</span>
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>

                <Card className="bg-card/50 backdrop-blur-lg border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className={`text-foreground flex items-center gap-2 ${isMobile ? 'text-lg' : 'text-xl'}`}>
                      <Vote className="w-5 h-5 text-blue-400" />
                      Governance Features
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="bg-primary/10 border border-primary/20 rounded-lg p-3">
                        <div className="text-primary font-semibold text-sm">Voting Power</div>
                        <div className="text-muted-foreground text-xs mt-1">(ASI x 0.3) + (NIGHT x 0.5) + (TON x 0.2)</div>
                      </div>
                      <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3">
                        <div className="text-blue-400 font-semibold text-sm">Proposal Types</div>
                        <div className="text-muted-foreground text-xs mt-1">Rates - Features - Partnerships - Treasury</div>
                      </div>
                      <div className="bg-chart-1/10 border border-chart-1/20 rounded-lg p-3">
                        <div className="text-chart-1 font-semibold text-sm">Voting Frequency</div>
                        <div className="text-muted-foreground text-xs mt-1">Monthly polls - Quarterly adjustments</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <footer className="border-t border-white/10 bg-background/30 backdrop-blur-xl py-8 px-4 sm:px-6 lg:px-8">
          <div className="max-w-6xl mx-auto">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
                  <Coins className="w-4 h-4 text-primary-foreground" />
                </div>
                <span className="font-semibold text-foreground">Vera Tokenomics</span>
              </div>
              <div className="text-muted-foreground text-sm">
                Built with privacy in mind - VERA
              </div>
            </div>
          </div>
        </footer>
      </div>
    </>
  );
}
