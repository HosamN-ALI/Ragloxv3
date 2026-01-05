// RAGLOX v3.0 - Plan View Component (Manus-style)
// Shows mission plan with task progress

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  ChevronDown, 
  ChevronUp, 
  CheckCircle2, 
  Circle, 
  Loader2,
  XCircle,
  Monitor,
  Terminal
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { PlanTask, TaskStatus } from "@/types";

interface PlanViewProps {
  tasks: PlanTask[];
  title?: string;
  subtitle?: string;
  onTaskClick?: (task: PlanTask) => void;
}

export function PlanView({ tasks, title = "Task progress", subtitle, onTaskClick }: PlanViewProps) {
  const [isExpanded, setIsExpanded] = useState(true);

  const completedTasks = tasks.filter(t => t.status === "completed").length;
  const totalTasks = tasks.length;
  const progressPercent = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;

  return (
    <div className="bg-card rounded-xl border border-border overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-border">
        <div className="flex items-center gap-3">
          {/* Icon */}
          <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center">
            <Monitor className="w-5 h-5 text-muted-foreground" />
          </div>

          {/* Title & Status */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="font-medium text-foreground">{title}</h3>
              {subtitle && (
                <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded">
                  {subtitle}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 mt-1">
              <Terminal className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">
                RAGLOX is using Terminal
              </span>
            </div>
          </div>

          {/* Progress Counter */}
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">
              {completedTasks}/{totalTasks}
            </span>
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="p-1 hover:bg-muted rounded transition-colors"
            >
              {isExpanded ? (
                <ChevronUp className="w-4 h-4 text-muted-foreground" />
              ) : (
                <ChevronDown className="w-4 h-4 text-muted-foreground" />
              )}
            </button>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mt-3 plan-progress">
          <motion.div
            className="plan-progress-bar"
            initial={{ width: 0 }}
            animate={{ width: `${progressPercent}%` }}
            transition={{ duration: 0.5, ease: "easeOut" }}
          />
        </div>
      </div>

      {/* Task List */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0 }}
            animate={{ height: "auto" }}
            exit={{ height: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="p-2">
              {tasks.map((task, index) => (
                <TaskItem
                  key={task.id}
                  task={task}
                  index={index}
                  onClick={() => onTaskClick?.(task)}
                />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Task Item Component
interface TaskItemProps {
  task: PlanTask;
  index: number;
  onClick?: () => void;
}

function TaskItem({ task, index, onClick }: TaskItemProps) {
  const getStatusIcon = (status: TaskStatus) => {
    switch (status) {
      case "completed":
        return <CheckCircle2 className="w-4 h-4 text-success" />;
      case "running":
        return <Loader2 className="w-4 h-4 text-primary animate-spin" />;
      case "failed":
        return <XCircle className="w-4 h-4 text-destructive" />;
      default:
        return <Circle className="w-4 h-4 text-muted-foreground" />;
    }
  };

  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full flex items-center gap-3 p-3 rounded-lg text-left transition-colors",
        "hover:bg-muted/50",
        task.status === "running" && "bg-primary/5"
      )}
    >
      {/* Status Icon */}
      <div className="flex-shrink-0">
        {getStatusIcon(task.status)}
      </div>

      {/* Task Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-foreground">
            {task.title}
          </span>
          {task.status === "completed" && (
            <CheckCircle2 className="w-3.5 h-3.5 text-success" />
          )}
        </div>
        {task.description && (
          <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
            {task.description}
          </p>
        )}
      </div>

      {/* Task Number */}
      <div className="flex-shrink-0 text-xs text-muted-foreground">
        #{index + 1}
      </div>
    </button>
  );
}

// Compact Plan Badge (for inline display in chat)
interface PlanBadgeProps {
  completedTasks: number;
  totalTasks: number;
  onClick?: () => void;
}

export function PlanBadge({ completedTasks, totalTasks, onClick }: PlanBadgeProps) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-muted hover:bg-muted/80 transition-colors"
    >
      <div className="w-5 h-5 rounded bg-card flex items-center justify-center">
        <Monitor className="w-3 h-3 text-muted-foreground" />
      </div>
      <span className="text-sm text-foreground">مظهر الخطة</span>
      <span className="text-xs text-muted-foreground">
        {completedTasks}/{totalTasks}
      </span>
      <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
    </button>
  );
}

export default PlanView;
