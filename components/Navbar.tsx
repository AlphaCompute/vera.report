import { useState, useRef, useEffect } from 'react'
import { createPortal } from 'react-dom'
import Link from 'next/link'
import { useRouter } from 'next/router'
import {
  ArrowRight,
  Github,
  ChevronDown,
  Coins,
  TrendingUp,
  Lock,
  Rocket
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { VeraLogo } from '@/components/vera/VeraLogo'

interface NavbarProps {
  onTokenomicsTabChange?: (tab: string) => void
  currentTokenomicsTab?: string
}

const tokenomicsSections = [
  { id: 'overview', label: 'Overview', icon: Coins, description: 'Token distribution and growth' },
  { id: 'rewards', label: 'Rewards', icon: TrendingUp, description: 'Earning mechanisms and tiers' },
  { id: 'staking', label: 'Staking', icon: Lock, description: 'Lock-up bonuses and APY' },
  { id: 'roadmap', label: 'Roadmap', icon: Rocket, description: 'Implementation phases' }
]

export default function Navbar({ onTokenomicsTabChange, currentTokenomicsTab }: NavbarProps) {
  const [isDropdownOpen, setIsDropdownOpen] = useState(false)
  const [dropdownPosition, setDropdownPosition] = useState({ top: 0, left: 0 })
  const buttonRef = useRef<HTMLButtonElement>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const router = useRouter()
  const isTokenomicsPage = router.pathname === '/tokenomics'
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node) &&
        buttonRef.current &&
        !buttonRef.current.contains(event.target as Node)
      ) {
        setIsDropdownOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Update dropdown position when opened or on scroll/resize
  useEffect(() => {
    const updatePosition = () => {
      if (buttonRef.current && isDropdownOpen) {
        const rect = buttonRef.current.getBoundingClientRect()
        setDropdownPosition({
          top: rect.bottom + 8,
          left: rect.left + rect.width / 2 - 128, // 128 = half of 256px (w-64)
        })
      }
    }

    updatePosition()
    window.addEventListener('scroll', updatePosition)
    window.addEventListener('resize', updatePosition)

    return () => {
      window.removeEventListener('scroll', updatePosition)
      window.removeEventListener('resize', updatePosition)
    }
  }, [isDropdownOpen])

  const handleTokenomicsClick = (sectionId: string) => {
    if (isTokenomicsPage && onTokenomicsTabChange) {
      onTokenomicsTabChange(sectionId)
      setIsDropdownOpen(false)
    } else {
      router.push(`/tokenomics?section=${sectionId}`)
      setIsDropdownOpen(false)
    }
  }

  const toggleDropdown = () => {
    if (!isDropdownOpen && buttonRef.current) {
      const rect = buttonRef.current.getBoundingClientRect()
      setDropdownPosition({
        top: rect.bottom + 8,
        left: rect.left + rect.width / 2 - 128,
      })
    }
    setIsDropdownOpen(!isDropdownOpen)
  }

  // Dropdown content rendered via portal
  const dropdownContent = isDropdownOpen && mounted ? createPortal(
    <div
      ref={dropdownRef}
      className="fixed z-[100] w-64 rounded-xl border border-white/10 shadow-2xl shadow-black/20"
      style={{
        top: dropdownPosition.top,
        left: dropdownPosition.left,
        backgroundColor: 'rgba(0, 0, 0, 0.5)',
        backdropFilter: 'blur(24px)',
        WebkitBackdropFilter: 'blur(24px)',
      }}
    >
      <div className="p-2">
        {tokenomicsSections.map((section) => (
          <button
            key={section.id}
            onClick={() => handleTokenomicsClick(section.id)}
            className={cn(
              "w-full flex items-start gap-3 p-3 rounded-lg transition-colors text-left",
              currentTokenomicsTab === section.id
                ? "bg-primary/10 text-primary"
                : "hover:bg-white/10"
            )}
          >
            <div className={cn(
              "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0",
              currentTokenomicsTab === section.id
                ? "bg-primary/20"
                : "bg-white/10"
            )}>
              <section.icon className={cn(
                "w-4 h-4",
                currentTokenomicsTab === section.id
                  ? "text-primary"
                  : "text-muted-foreground"
              )} />
            </div>
            <div>
              <div className={cn(
                "font-medium text-sm",
                currentTokenomicsTab === section.id
                  ? "text-primary"
                  : "text-foreground"
              )}>
                {section.label}
              </div>
              <div className="text-xs text-muted-foreground">
                {section.description}
              </div>
            </div>
          </button>
        ))}
      </div>
      <div className="border-t border-white/10 p-2">
        <Link
          href="/tokenomics"
          onClick={() => setIsDropdownOpen(false)}
          className="flex items-center justify-center gap-2 w-full p-2 text-sm text-primary hover:bg-primary/10 rounded-lg transition-colors"
        >
          View All Tokenomics
          <ArrowRight className="w-4 h-4" />
        </Link>
      </div>
    </div>,
    document.body
  ) : null

  return (
    <>
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-white/10 bg-background/40 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link href="/">
              <VeraLogo size="sm" linked={false} />
            </Link>

            <div className="hidden md:flex items-center gap-6">
              <a href="/#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Features
              </a>
              <a href="/#use-cases" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Use Cases
              </a>
              <a href="/#developers" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Developers
              </a>

              {/* Tokenomics Dropdown Trigger */}
              <button
                ref={buttonRef}
                onClick={toggleDropdown}
                className={cn(
                  "flex items-center gap-1 text-sm transition-colors",
                  isTokenomicsPage
                    ? "text-foreground font-medium"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                Tokenomics
                <ChevronDown className={cn(
                  "w-4 h-4 transition-transform",
                  isDropdownOpen && "rotate-180"
                )} />
              </button>
            </div>

            <div className="flex items-center gap-3">
              <a
                href="https://github.com/AlphaTONCapital/vera"
                target="_blank"
                rel="noopener noreferrer"
                className="hidden sm:flex"
              >
                <Button variant="ghost" size="icon">
                  <Github className="w-5 h-5" />
                </Button>
              </a>
              <Link href="/report">
                <Button className="gap-2">
                  Launch App
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Dropdown rendered via portal */}
      {dropdownContent}
    </>
  )
}
