import React from 'react';
const ProgressBar = ({ progress }) => {
    return (<div className="w-full bg-gray-200 rounded-full h-2.5 overflow-hidden">
      <div className="bg-indigo-600 h-2.5 rounded-full transition-all duration-300 ease-in-out" style={{ width: `${progress}%` }}></div>
    </div>);
};
export default ProgressBar;
