export interface DashboardStats {
  activeJobs: number;
  screenedCandidates: number;
  approvedCandidates: number;
  averageTime: number;
}

export interface StatCardData {
  title: string;
  value: string | number;
  iconName: string;
  iconColor: string;
  iconBg: string;
}