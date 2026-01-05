// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Plan View Component
// Manus-inspired task progress panel (مظهر الخطة)
// Shows mission plan with collapsible task list
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Circle,
  Loader2,
  XCircle,
  Terminal,
  Bot,
  Cpu,
  ListTodo,
  Expand,
  Minimize2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { motion, AnimatePresence } from 'framer-motion'

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

export type TaskStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped'

export interface PlanTask {
  id: string
  title: string
  description?: string
  status: TaskStatus
  progress?: number // 0-100
  subtasks?: PlanTask[]
  command?: string
  startTime?: string
  endTime?: string
}

export interface PlanData {
  id: string
  title: string
  description?: string
  computerName: string
  isUsingTerminal: boolean
  tasks: PlanTask[]
  totalTasks: number
  completedTasks: number
}

interface PlanViewProps {
  plan: PlanData
  isExpanded?: boolean
  onToggleExpand?: () => void
  onTaskClick?: (task: PlanTask) => void
  className?: string
}

// ═══════════════════════════════════════════════════════════════
// Task Status Icon
// ═══════════════════════════════════════════════════════════════

function TaskStatusIcon({ status }: { status: TaskStatus }) {
  switch (status) {
    case 'completed':
      return <CheckCircle2 className="h-4 w-4 text-green-400" />
    case 'in_progress':
      return <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
    case 'pending':
      return <Circle className="h-4 w-4 text-zinc-500" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-red-400" />
    case 'skipped':
      return <Circle className="h-4 w-4 text-zinc-600" strokeDasharray="4" />
    default:
      return <Circle className="h-4 w-4 text-zinc-500" />
  }
}

// ═══════════════════════════════════════════════════════════════
// Task Item Component
// ═══════════════════════════════════════════════════════════════

interface TaskItemProps {
  task: PlanTask
  index: number
  onClick?: (task: PlanTask) => void
}

function TaskItem({ task, onClick }: TaskItemProps) {
  const [isExpanded, setIsExpanded] = React.useState(false)
  const hasSubtasks = task.subtasks && task.subtasks.length > 0
  
  return (
    <div className="relative">
      {/* Main Task */}
      <button
        onClick={() => {
          if (hasSubtasks) {
            setIsExpanded(!isExpanded)
          } else {
            onClick?.(task)
          }
        }}
        className={cn(
          "w-full flex items-start gap-3 p-2 rounded-lg text-left transition-all",
          "hover:bg-zinc-800/50",
          task.status === 'in_progress' && "bg-blue-500/5"
        )}
      >
        {/* Status Icon */}
        <div className="flex-shrink-0 mt-0.5">
          <TaskStatusIcon status={task.status} />
        </div>
        
        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={cn(
              "text-sm",
              task.status === 'completed' && "text-green-400",
              task.status === 'in_progress' && "text-white",
              task.status === 'pending' && "text-zinc-400",
              task.status === 'failed' && "text-red-400",
              task.status === 'skipped' && "text-zinc-600 line-through"
            )}>
              {task.title}
            </span>
            
            {task.status === 'in_progress' && task.progress !== undefined && (
              <span className="text-xs text-blue-400">
                {task.progress}%
              </span>
            )}
          </div>
          
          {task.description && (
            <p className="text-xs text-zinc-500 mt-0.5 line-clamp-1">
              {task.description}
            </p>
          )}
        </div>
        
        {/* Expand Arrow for subtasks */}
        {hasSubtasks && (
          <div className="flex-shrink-0 text-zinc-500">
            {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </div>
        )}
      </button>
      
      {/* Subtasks */}
      <AnimatePresence>
        {isExpanded && hasSubtasks && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden pl-7 mt-1 space-y-1"
          >
            {task.subtasks!.map((subtask, subIndex) => (
              <TaskItem
                key={subtask.id}
                task={subtask}
                index={subIndex}
                onClick={onClick}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Plan Header Component
// ═══════════════════════════════════════════════════════════════

interface PlanHeaderProps {
  plan: PlanData
  isExpanded: boolean
  onToggle: () => void
}

function PlanHeader({ plan, isExpanded, onToggle }: PlanHeaderProps) {
  return (
    <div className="flex items-center justify-between p-4 border-b border-zinc-800">
      <div className="flex items-center gap-3">
        {/* Computer Icon */}
        <div className="relative">
          <div className="p-2 rounded-lg bg-zinc-800">
            <Cpu className="h-5 w-5 text-zinc-400" />
          </div>
          {plan.isUsingTerminal && (
            <div className="absolute -bottom-1 -right-1 p-0.5 rounded bg-green-500">
              <Terminal className="h-2.5 w-2.5 text-white" />
            </div>
          )}
        </div>
        
        {/* Title */}
        <div>
          <h3 className="text-sm font-medium text-white">{plan.computerName}</h3>
          <p className="text-xs text-zinc-500 flex items-center gap-1">
            <Bot className="h-3 w-3" />
            {plan.isUsingTerminal ? 'Using Terminal' : 'Processing...'}
          </p>
        </div>
      </div>
      
      {/* Expand/Collapse */}
      <button
        onClick={onToggle}
        className="p-2 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors"
      >
        {isExpanded ? <Minimize2 className="h-4 w-4" /> : <Expand className="h-4 w-4" />}
      </button>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Progress Summary
// ═══════════════════════════════════════════════════════════════

interface ProgressSummaryProps {
  completedTasks: number
  totalTasks: number
}

function ProgressSummary({ completedTasks, totalTasks }: ProgressSummaryProps) {
  const progress = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0
  
  return (
    <div className="px-4 py-3 border-b border-zinc-800">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-zinc-400 flex items-center gap-1">
          <ListTodo className="h-3 w-3" />
          Task progress
        </span>
        <span className="text-xs text-zinc-300 font-mono">
          {completedTasks} / {totalTasks}
        </span>
      </div>
      
      {/* Progress Bar */}
      <div className="h-1 bg-zinc-800 rounded-full overflow-hidden">
        <motion.div
          className="h-full bg-green-500"
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.5 }}
        />
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Plan View Component
// ═══════════════════════════════════════════════════════════════

export function PlanView({
  plan,
  isExpanded: controlledExpanded,
  onToggleExpand,
  onTaskClick,
  className
}: PlanViewProps) {
  const [internalExpanded, setInternalExpanded] = React.useState(true)
  
  // Support both controlled and uncontrolled modes
  const isExpanded = controlledExpanded ?? internalExpanded
  const handleToggle = onToggleExpand ?? (() => setInternalExpanded(!internalExpanded))
  
  return (
    <motion.div
      layout
      className={cn(
        "bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden",
        className
      )}
    >
      {/* Header */}
      <PlanHeader
        plan={plan}
        isExpanded={isExpanded}
        onToggle={handleToggle}
      />
      
      {/* Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            {/* Progress Summary */}
            <ProgressSummary
              completedTasks={plan.completedTasks}
              totalTasks={plan.totalTasks}
            />
            
            {/* Task List */}
            <div className="p-4 space-y-1 max-h-[400px] overflow-y-auto scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-transparent">
              {plan.tasks.map((task, index) => (
                <TaskItem
                  key={task.id}
                  task={task}
                  index={index}
                  onClick={onTaskClick}
                />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      
      {/* Collapsed Summary */}
      <AnimatePresence>
        {!isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="px-4 py-3"
          >
            <div className="flex items-center justify-between text-xs text-zinc-400">
              <span>{plan.completedTasks} of {plan.totalTasks} tasks completed</span>
              <span className="text-green-400">{Math.round((plan.completedTasks / plan.totalTasks) * 100)}%</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Compact Plan Badge (for chat messages)
// ═══════════════════════════════════════════════════════════════

interface PlanBadgeProps {
  plan: PlanData
  onClick?: () => void
}

export function PlanBadge({ plan, onClick }: PlanBadgeProps) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg hover:bg-zinc-700 transition-colors"
    >
      <div className="relative">
        <Cpu className="h-4 w-4 text-zinc-400" />
        {plan.isUsingTerminal && (
          <span className="absolute -top-1 -right-1 h-2 w-2 bg-green-500 rounded-full" />
        )}
      </div>
      
      <div className="text-left">
        <span className="text-xs text-white block">{plan.computerName}</span>
        <span className="text-[10px] text-zinc-500">
          {plan.completedTasks}/{plan.totalTasks} tasks • {Math.round((plan.completedTasks / plan.totalTasks) * 100)}%
        </span>
      </div>
      
      <ChevronRight className="h-4 w-4 text-zinc-500" />
    </button>
  )
}

export default PlanView
