// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Mission Setup Wizard Component
// Guided mission configuration for empty state
// Design: Step-by-step wizard: Define Scope → Select Intensity → Launch
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { useState, useCallback } from 'react'
import {
  Rocket,
  Target,
  Shield,
  Zap,
  ChevronRight,
  ChevronLeft,
  Check,
  Plus,
  X,
  AlertTriangle,
  Info,
  Server,
  Network,
  Globe,
  Eye,
  Crosshair,
  Key,
  FileSearch,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useMissionStore } from '@/stores/missionStore'

// ═══════════════════════════════════════════════════════════════
// Wizard Step Types
// ═══════════════════════════════════════════════════════════════

type WizardStep = 'scope' | 'goals' | 'intensity' | 'review'

interface StepConfig {
  id: WizardStep
  title: string
  description: string
  icon: React.ElementType
}

const steps: StepConfig[] = [
  { id: 'scope', title: 'Define Scope', description: 'Target IP ranges and networks', icon: Target },
  { id: 'goals', title: 'Set Goals', description: 'Mission objectives', icon: Crosshair },
  { id: 'intensity', title: 'Select Intensity', description: 'Operation aggressiveness', icon: Zap },
  { id: 'review', title: 'Review & Launch', description: 'Confirm configuration', icon: Rocket },
]

// ═══════════════════════════════════════════════════════════════
// Intensity Configuration
// ═══════════════════════════════════════════════════════════════

interface IntensityOption {
  id: 'stealth' | 'balanced' | 'aggressive'
  title: string
  description: string
  icon: React.ElementType
  color: string
  bgColor: string
  borderColor: string
  features: string[]
  warnings: string[]
}

const intensityOptions: IntensityOption[] = [
  {
    id: 'stealth',
    title: 'Stealth',
    description: 'Low and slow approach to minimize detection',
    icon: Eye,
    color: 'text-cyan-400',
    bgColor: 'bg-cyan-500/10',
    borderColor: 'border-cyan-500/30',
    features: [
      'Slow scan rates',
      'No aggressive exploitation',
      'Minimal footprint',
      'Longer execution time',
    ],
    warnings: [],
  },
  {
    id: 'balanced',
    title: 'Balanced',
    description: 'Moderate approach balancing speed and stealth',
    icon: Shield,
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/30',
    features: [
      'Standard scan rates',
      'Targeted exploitation',
      'Reasonable footprint',
      'Balanced execution time',
    ],
    warnings: [
      'May trigger some IDS alerts',
    ],
  },
  {
    id: 'aggressive',
    title: 'Aggressive',
    description: 'Fast and comprehensive attack approach',
    icon: Zap,
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    features: [
      'Fast parallel scanning',
      'All exploitation attempts',
      'Maximum coverage',
      'Shortest execution time',
    ],
    warnings: [
      'Will trigger IDS/IPS alerts',
      'May cause service disruption',
      'Higher detection risk',
    ],
  },
]

// ═══════════════════════════════════════════════════════════════
// Goal Options
// ═══════════════════════════════════════════════════════════════

interface GoalOption {
  id: string
  title: string
  description: string
  icon: React.ElementType
  color: string
}

const goalOptions: GoalOption[] = [
  { id: 'initial_access', title: 'Initial Access', description: 'Gain first foothold on target', icon: Target, color: 'text-blue-400' },
  { id: 'credential_access', title: 'Credential Access', description: 'Harvest user credentials', icon: Key, color: 'text-yellow-400' },
  { id: 'privilege_escalation', title: 'Privilege Escalation', description: 'Elevate to admin/root', icon: Shield, color: 'text-orange-400' },
  { id: 'lateral_movement', title: 'Lateral Movement', description: 'Pivot to other systems', icon: Network, color: 'text-purple-400' },
  { id: 'data_exfiltration', title: 'Data Exfiltration', description: 'Extract sensitive data', icon: FileSearch, color: 'text-red-400' },
  { id: 'persistence', title: 'Persistence', description: 'Maintain long-term access', icon: Server, color: 'text-green-400' },
]

// ═══════════════════════════════════════════════════════════════
// Step Progress Indicator
// ═══════════════════════════════════════════════════════════════

interface StepProgressProps {
  currentStep: WizardStep
  completedSteps: Set<WizardStep>
  onStepClick: (step: WizardStep) => void
}

function StepProgress({ currentStep, completedSteps, onStepClick }: StepProgressProps) {
  const currentIndex = steps.findIndex(s => s.id === currentStep)
  
  return (
    <div className="flex items-center justify-between mb-8">
      {steps.map((step, index) => {
        const Icon = step.icon
        const isCompleted = completedSteps.has(step.id)
        const isCurrent = step.id === currentStep
        const isClickable = index <= currentIndex || isCompleted
        
        return (
          <React.Fragment key={step.id}>
            {/* Step Node */}
            <button
              onClick={() => isClickable && onStepClick(step.id)}
              disabled={!isClickable}
              className={cn(
                'flex flex-col items-center gap-2 transition-all',
                isClickable ? 'cursor-pointer' : 'cursor-not-allowed'
              )}
            >
              <div className={cn(
                'w-12 h-12 rounded-xl border-2 flex items-center justify-center transition-all',
                isCompleted && 'bg-green-500/20 border-green-500',
                isCurrent && !isCompleted && 'bg-royal-blue/20 border-royal-blue',
                !isCurrent && !isCompleted && 'bg-zinc-800 border-zinc-700'
              )}>
                {isCompleted ? (
                  <Check className="h-6 w-6 text-green-400" />
                ) : (
                  <Icon className={cn(
                    'h-6 w-6',
                    isCurrent ? 'text-royal-blue' : 'text-zinc-500'
                  )} />
                )}
              </div>
              <div className="text-center">
                <p className={cn(
                  'text-xs font-semibold',
                  isCurrent ? 'text-text-primary-dark' : 'text-text-muted-dark'
                )}>
                  {step.title}
                </p>
                <p className="text-[10px] text-text-muted-dark hidden sm:block">
                  {step.description}
                </p>
              </div>
            </button>
            
            {/* Connector */}
            {index < steps.length - 1 && (
              <div className={cn(
                'flex-1 h-0.5 mx-2 rounded-full',
                completedSteps.has(steps[index + 1].id) || steps[index + 1].id === currentStep
                  ? 'bg-royal-blue/50'
                  : 'bg-zinc-700'
              )} />
            )}
          </React.Fragment>
        )
      })}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Step 1: Scope Definition
// ═══════════════════════════════════════════════════════════════

interface ScopeStepProps {
  scope: string[]
  missionName: string
  onScopeChange: (scope: string[]) => void
  onNameChange: (name: string) => void
}

function ScopeStep({ scope, missionName, onScopeChange, onNameChange }: ScopeStepProps) {
  const [inputValue, setInputValue] = useState('')
  const [error, setError] = useState<string | null>(null)
  
  const validateAndAdd = () => {
    const value = inputValue.trim()
    if (!value) return
    
    // Basic validation (IP, CIDR, or hostname)
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/
    const hostnameRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/
    
    if (!ipRegex.test(value) && !hostnameRegex.test(value)) {
      setError('Invalid IP address, CIDR notation, or hostname')
      return
    }
    
    if (scope.includes(value)) {
      setError('Target already in scope')
      return
    }
    
    setError(null)
    onScopeChange([...scope, value])
    setInputValue('')
  }
  
  const removeTarget = (target: string) => {
    onScopeChange(scope.filter(s => s !== target))
  }
  
  return (
    <div className="space-y-6">
      {/* Mission Name */}
      <div>
        <label className="block text-sm font-semibold text-text-secondary-dark mb-2">
          Mission Name
        </label>
        <input
          type="text"
          value={missionName}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="e.g., Internal Network Assessment"
          className={cn(
            'w-full px-4 py-3 rounded-xl text-sm',
            'bg-zinc-800 border border-zinc-700 text-text-primary-dark',
            'placeholder:text-text-muted-dark',
            'focus:outline-none focus:border-royal-blue focus:ring-1 focus:ring-royal-blue/50'
          )}
        />
      </div>
      
      {/* Target Input */}
      <div>
        <label className="block text-sm font-semibold text-text-secondary-dark mb-2">
          Add Targets
        </label>
        <div className="flex gap-2">
          <input
            type="text"
            value={inputValue}
            onChange={(e) => { setInputValue(e.target.value); setError(null); }}
            onKeyDown={(e) => e.key === 'Enter' && validateAndAdd()}
            placeholder="IP address, CIDR (e.g., 192.168.1.0/24), or hostname"
            className={cn(
              'flex-1 px-4 py-3 rounded-xl text-sm',
              'bg-zinc-800 border text-text-primary-dark',
              'placeholder:text-text-muted-dark',
              'focus:outline-none focus:ring-1',
              error 
                ? 'border-red-500 focus:border-red-500 focus:ring-red-500/50'
                : 'border-zinc-700 focus:border-royal-blue focus:ring-royal-blue/50'
            )}
          />
          <button
            onClick={validateAndAdd}
            className={cn(
              'px-4 py-3 rounded-xl font-semibold text-sm transition-all',
              'bg-royal-blue text-white hover:bg-royal-blue/80',
              'focus:outline-none focus:ring-2 focus:ring-royal-blue/50'
            )}
          >
            <Plus className="h-5 w-5" />
          </button>
        </div>
        {error && (
          <p className="mt-2 text-xs text-red-400 flex items-center gap-1">
            <AlertTriangle className="h-3 w-3" />
            {error}
          </p>
        )}
      </div>
      
      {/* Target List */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-sm font-semibold text-text-secondary-dark">
            Scope ({scope.length} target{scope.length !== 1 ? 's' : ''})
          </label>
          {scope.length > 0 && (
            <button
              onClick={() => onScopeChange([])}
              className="text-xs text-red-400 hover:text-red-300 transition-colors"
            >
              Clear all
            </button>
          )}
        </div>
        
        {scope.length === 0 ? (
          <div className="p-8 rounded-xl border border-dashed border-zinc-700 text-center">
            <Globe className="h-8 w-8 text-text-muted-dark mx-auto mb-2" />
            <p className="text-sm text-text-muted-dark">
              No targets defined yet
            </p>
            <p className="text-xs text-text-muted-dark mt-1">
              Add IP addresses or networks to begin
            </p>
          </div>
        ) : (
          <div className="space-y-2 max-h-48 overflow-y-auto pr-2">
            {scope.map((target) => (
              <div
                key={target}
                className={cn(
                  'flex items-center justify-between px-4 py-3 rounded-xl',
                  'bg-zinc-800/50 border border-zinc-700'
                )}
              >
                <div className="flex items-center gap-3">
                  <Server className="h-4 w-4 text-text-muted-dark" />
                  <span className="text-sm font-mono text-text-primary-dark">{target}</span>
                </div>
                <button
                  onClick={() => removeTarget(target)}
                  className="p-1 rounded hover:bg-zinc-700 text-text-muted-dark hover:text-red-400 transition-colors"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Step 2: Goals Selection
// ═══════════════════════════════════════════════════════════════

interface GoalsStepProps {
  selectedGoals: string[]
  onGoalsChange: (goals: string[]) => void
}

function GoalsStep({ selectedGoals, onGoalsChange }: GoalsStepProps) {
  const toggleGoal = (goalId: string) => {
    if (selectedGoals.includes(goalId)) {
      onGoalsChange(selectedGoals.filter(g => g !== goalId))
    } else {
      onGoalsChange([...selectedGoals, goalId])
    }
  }
  
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary-dark mb-4">
        Select one or more objectives for this mission. The AI will prioritize actions to achieve these goals.
      </p>
      
      <div className="grid grid-cols-2 gap-3">
        {goalOptions.map((goal) => {
          const Icon = goal.icon
          const isSelected = selectedGoals.includes(goal.id)
          
          return (
            <button
              key={goal.id}
              onClick={() => toggleGoal(goal.id)}
              className={cn(
                'p-4 rounded-xl border text-left transition-all',
                isSelected
                  ? 'bg-royal-blue/10 border-royal-blue ring-1 ring-royal-blue/50'
                  : 'bg-zinc-800/50 border-zinc-700 hover:border-zinc-600'
              )}
            >
              <div className="flex items-start gap-3">
                <div className={cn(
                  'p-2 rounded-lg',
                  isSelected ? 'bg-royal-blue/20' : 'bg-zinc-700/50'
                )}>
                  <Icon className={cn('h-5 w-5', isSelected ? 'text-royal-blue' : goal.color)} />
                </div>
                <div className="flex-1 min-w-0">
                  <h4 className={cn(
                    'text-sm font-semibold',
                    isSelected ? 'text-text-primary-dark' : 'text-text-secondary-dark'
                  )}>
                    {goal.title}
                  </h4>
                  <p className="text-xs text-text-muted-dark mt-0.5">
                    {goal.description}
                  </p>
                </div>
                {isSelected && (
                  <Check className="h-5 w-5 text-royal-blue flex-shrink-0" />
                )}
              </div>
            </button>
          )
        })}
      </div>
      
      {selectedGoals.length === 0 && (
        <div className="flex items-center gap-2 p-3 rounded-xl bg-amber-500/10 border border-amber-500/30">
          <Info className="h-4 w-4 text-amber-400" />
          <p className="text-xs text-amber-300">
            Select at least one goal to continue
          </p>
        </div>
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Step 3: Intensity Selection
// ═══════════════════════════════════════════════════════════════

interface IntensityStepProps {
  intensity: 'stealth' | 'balanced' | 'aggressive'
  onIntensityChange: (intensity: 'stealth' | 'balanced' | 'aggressive') => void
}

function IntensityStep({ intensity, onIntensityChange }: IntensityStepProps) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary-dark mb-4">
        Select the operation intensity level based on your engagement rules and risk tolerance.
      </p>
      
      <div className="space-y-3">
        {intensityOptions.map((option) => {
          const Icon = option.icon
          const isSelected = intensity === option.id
          
          return (
            <button
              key={option.id}
              onClick={() => onIntensityChange(option.id)}
              className={cn(
                'w-full p-4 rounded-xl border text-left transition-all',
                isSelected
                  ? cn(option.bgColor, 'border-2', option.borderColor.replace('/30', ''))
                  : 'bg-zinc-800/50 border-zinc-700 hover:border-zinc-600'
              )}
            >
              <div className="flex items-start gap-4">
                <div className={cn(
                  'p-3 rounded-xl',
                  isSelected ? option.bgColor : 'bg-zinc-700/50'
                )}>
                  <Icon className={cn('h-6 w-6', isSelected ? option.color : 'text-text-muted-dark')} />
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h4 className={cn(
                      'text-base font-semibold',
                      isSelected ? option.color : 'text-text-secondary-dark'
                    )}>
                      {option.title}
                    </h4>
                    {isSelected && (
                      <Check className={cn('h-5 w-5', option.color)} />
                    )}
                  </div>
                  <p className="text-sm text-text-muted-dark mt-1">
                    {option.description}
                  </p>
                  
                  <div className="mt-3 space-y-2">
                    <div className="flex flex-wrap gap-2">
                      {option.features.map((feature, idx) => (
                        <span
                          key={idx}
                          className={cn(
                            'text-[10px] px-2 py-1 rounded-full',
                            isSelected
                              ? cn(option.bgColor, option.color)
                              : 'bg-zinc-700/50 text-text-muted-dark'
                          )}
                        >
                          {feature}
                        </span>
                      ))}
                    </div>
                    
                    {option.warnings.length > 0 && (
                      <div className="flex items-start gap-1.5 mt-2">
                        <AlertTriangle className="h-3 w-3 text-amber-400 mt-0.5 flex-shrink-0" />
                        <p className="text-[10px] text-amber-400">
                          {option.warnings.join(' • ')}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Step 4: Review & Launch
// ═══════════════════════════════════════════════════════════════

interface ReviewStepProps {
  missionName: string
  scope: string[]
  goals: string[]
  intensity: 'stealth' | 'balanced' | 'aggressive'
  isLaunching: boolean
  onLaunch: () => void
}

function ReviewStep({ missionName, scope, goals, intensity, isLaunching, onLaunch }: ReviewStepProps) {
  const intensityOption = intensityOptions.find(o => o.id === intensity)!
  const IntensityIcon = intensityOption.icon
  
  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-4">
        {/* Mission Name */}
        <div className="p-4 rounded-xl bg-zinc-800/50 border border-zinc-700">
          <p className="text-xs text-text-muted-dark uppercase tracking-wider mb-1">Mission</p>
          <p className="text-sm font-semibold text-text-primary-dark truncate">
            {missionName || 'Unnamed Mission'}
          </p>
        </div>
        
        {/* Intensity */}
        <div className={cn('p-4 rounded-xl border', intensityOption.bgColor, intensityOption.borderColor)}>
          <p className="text-xs text-text-muted-dark uppercase tracking-wider mb-1">Intensity</p>
          <div className="flex items-center gap-2">
            <IntensityIcon className={cn('h-4 w-4', intensityOption.color)} />
            <p className={cn('text-sm font-semibold', intensityOption.color)}>
              {intensityOption.title}
            </p>
          </div>
        </div>
      </div>
      
      {/* Scope */}
      <div className="p-4 rounded-xl bg-zinc-800/50 border border-zinc-700">
        <p className="text-xs text-text-muted-dark uppercase tracking-wider mb-2">
          Scope ({scope.length} target{scope.length !== 1 ? 's' : ''})
        </p>
        <div className="flex flex-wrap gap-2">
          {scope.map((target) => (
            <span key={target} className="px-2 py-1 rounded-lg bg-zinc-700/50 text-xs font-mono text-text-secondary-dark">
              {target}
            </span>
          ))}
        </div>
      </div>
      
      {/* Goals */}
      <div className="p-4 rounded-xl bg-zinc-800/50 border border-zinc-700">
        <p className="text-xs text-text-muted-dark uppercase tracking-wider mb-2">
          Goals ({goals.length})
        </p>
        <div className="flex flex-wrap gap-2">
          {goals.map((goalId) => {
            const goal = goalOptions.find(g => g.id === goalId)!
            const Icon = goal.icon
            return (
              <span key={goalId} className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-zinc-700/50 text-xs">
                <Icon className={cn('h-3 w-3', goal.color)} />
                <span className="text-text-secondary-dark">{goal.title}</span>
              </span>
            )
          })}
        </div>
      </div>
      
      {/* Launch Button */}
      <button
        onClick={onLaunch}
        disabled={isLaunching}
        className={cn(
          'w-full flex items-center justify-center gap-3 px-6 py-4 rounded-xl',
          'bg-gradient-to-r from-royal-blue to-blue-600 text-white',
          'font-bold text-lg transition-all',
          'hover:from-royal-blue/90 hover:to-blue-500',
          'focus:outline-none focus:ring-4 focus:ring-royal-blue/50',
          'disabled:opacity-50 disabled:cursor-not-allowed'
        )}
      >
        {isLaunching ? (
          <>
            <div className="h-6 w-6 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            Launching Mission...
          </>
        ) : (
          <>
            <Rocket className="h-6 w-6" />
            Launch Mission
          </>
        )}
      </button>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Mission Setup Wizard Component
// ═══════════════════════════════════════════════════════════════

export interface MissionSetupWizardProps {
  onLaunch?: (config: {
    name: string
    scope: string[]
    goals: string[]
    intensity: 'stealth' | 'balanced' | 'aggressive'
  }) => Promise<void>
}

export function MissionSetupWizard({ onLaunch }: MissionSetupWizardProps) {
  const initMission = useMissionStore(s => s.initMission)
  
  const [currentStep, setCurrentStep] = useState<WizardStep>('scope')
  const [completedSteps, setCompletedSteps] = useState<Set<WizardStep>>(new Set())
  const [isLaunching, setIsLaunching] = useState(false)
  
  // Form state
  const [missionName, setMissionName] = useState('')
  const [scope, setScope] = useState<string[]>([])
  const [goals, setGoals] = useState<string[]>(['initial_access'])
  const [intensity, setIntensity] = useState<'stealth' | 'balanced' | 'aggressive'>('balanced')
  
  const currentStepIndex = steps.findIndex(s => s.id === currentStep)
  
  const canProceed = useCallback(() => {
    switch (currentStep) {
      case 'scope':
        return missionName.trim() !== '' && scope.length > 0
      case 'goals':
        return goals.length > 0
      case 'intensity':
        return true
      case 'review':
        return true
      default:
        return false
    }
  }, [currentStep, missionName, scope, goals])
  
  const handleNext = () => {
    if (!canProceed()) return
    
    setCompletedSteps(prev => new Set([...prev, currentStep]))
    
    if (currentStepIndex < steps.length - 1) {
      setCurrentStep(steps[currentStepIndex + 1].id)
    }
  }
  
  const handleBack = () => {
    if (currentStepIndex > 0) {
      setCurrentStep(steps[currentStepIndex - 1].id)
    }
  }
  
  const handleLaunch = async () => {
    setIsLaunching(true)
    
    try {
      const config = {
        name: missionName || 'Unnamed Mission',
        scope,
        goals,
        intensity,
      }
      
      // Initialize in store
      initMission(config)
      
      // Call external handler
      await onLaunch?.(config)
    } catch (error) {
      console.error('Failed to launch mission:', error)
    } finally {
      setIsLaunching(false)
    }
  }
  
  return (
    <div className="max-w-2xl mx-auto p-6">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-royal-blue/10 border border-royal-blue/30 mb-4">
          <Rocket className="h-8 w-8 text-royal-blue" />
        </div>
        <h1 className="text-2xl font-bold text-text-primary-dark mb-2">
          Mission Setup
        </h1>
        <p className="text-sm text-text-muted-dark">
          Configure your red team operation parameters
        </p>
      </div>
      
      {/* Step Progress */}
      <StepProgress
        currentStep={currentStep}
        completedSteps={completedSteps}
        onStepClick={setCurrentStep}
      />
      
      {/* Step Content */}
      <div className="bg-zinc-900/50 rounded-2xl border border-zinc-800 p-6 mb-6">
        {currentStep === 'scope' && (
          <ScopeStep
            scope={scope}
            missionName={missionName}
            onScopeChange={setScope}
            onNameChange={setMissionName}
          />
        )}
        
        {currentStep === 'goals' && (
          <GoalsStep
            selectedGoals={goals}
            onGoalsChange={setGoals}
          />
        )}
        
        {currentStep === 'intensity' && (
          <IntensityStep
            intensity={intensity}
            onIntensityChange={setIntensity}
          />
        )}
        
        {currentStep === 'review' && (
          <ReviewStep
            missionName={missionName}
            scope={scope}
            goals={goals}
            intensity={intensity}
            isLaunching={isLaunching}
            onLaunch={handleLaunch}
          />
        )}
      </div>
      
      {/* Navigation Buttons */}
      {currentStep !== 'review' && (
        <div className="flex justify-between">
          <button
            onClick={handleBack}
            disabled={currentStepIndex === 0}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition-all',
              currentStepIndex === 0
                ? 'text-text-muted-dark cursor-not-allowed'
                : 'text-text-secondary-dark hover:text-text-primary-dark hover:bg-zinc-800'
            )}
          >
            <ChevronLeft className="h-4 w-4" />
            Back
          </button>
          
          <button
            onClick={handleNext}
            disabled={!canProceed()}
            className={cn(
              'flex items-center gap-2 px-6 py-2 rounded-xl text-sm font-semibold transition-all',
              canProceed()
                ? 'bg-royal-blue text-white hover:bg-royal-blue/80'
                : 'bg-zinc-800 text-text-muted-dark cursor-not-allowed'
            )}
          >
            Continue
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  )
}

export default MissionSetupWizard
