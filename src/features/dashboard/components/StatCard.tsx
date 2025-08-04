import React from 'react';
import { Briefcase, Users, CheckCircle2, Clock, Award, LucideProps } from 'lucide-react';

// Adicionando o ícone 'Award' (prêmio/troféu)
const iconMap: Record<string, React.FC<LucideProps>> = {
  briefcase: Briefcase,
  users: Users,
  check: CheckCircle2,
  clock: Clock,
  award: Award 
};

interface StatCardProps {
  title: string;
  value: string | number;
  iconName: string;
  iconColor: string;
  iconBg: string;
  onClick?: () => void; // Propriedade opcional para o clique
}

const StatCard: React.FC<StatCardProps> = ({ 
  title, 
  value, 
  iconName,
  iconColor, 
  iconBg,
  onClick
}) => {
  const Icon = iconMap[iconName] || Briefcase;

  const cardContent = (
    <div className="flex items-center text-left w-full">
      <div className={`p-3 rounded-lg ${iconBg}`}>
        <Icon className={iconColor} size={24} />
      </div>
      <div className="ml-4">
        <p className="text-sm font-medium text-gray-500">{title}</p>
        <p className="text-2xl font-bold text-gray-800">{value}</p>
      </div>
    </div>
  );

  // Se a propriedade onClick for fornecida, renderiza como um botão
  if (onClick) {
    return (
      <button 
        onClick={onClick}
        // Adicionamos um cursor-pointer para deixar claro que é clicável
        className="bg-white p-5 rounded-lg shadow-sm border border-gray-100 w-full hover:shadow-md hover:border-indigo-200 transition-all focus:outline-none focus:ring-2 focus:ring-indigo-500 cursor-pointer"
        // Desabilitamos o botão se o valor for 0 para uma melhor UX
        disabled={Number(value) === 0}
      >
        {cardContent}
      </button>
    );
  }

  // Caso contrário, renderiza como uma div normal
  return (
    <div className="bg-white p-5 rounded-lg shadow-sm border border-gray-100 flex items-center">
      {cardContent}
    </div>
  );
};

export default StatCard;
